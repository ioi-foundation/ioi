use super::{
    ensure_agent_running_or_resume_retry_pause, handle_step, maybe_direct_inline_author_tool_call,
    maybe_route_contract_local_install_tool_call, maybe_run_optimizer_recovery,
    queue_parent_playbook_await_request, queue_root_playbook_delegate_request,
    should_clear_stale_canonical_pending,
};
use crate::agentic::runtime::keys::{get_parent_playbook_run_key, get_state_key};
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, ExecutionTier, ParentPlaybookRun, ParentPlaybookStatus,
    StepAgentParams,
};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::state::{StateAccess, StateScanIter};
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_types::app::agentic::{
    ArgumentOrigin, CapabilityId, InferenceOptions, InstructionBindingKind, InstructionContract,
    InstructionSlotBinding, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::app::{
    AccountId, ActionContext, ActionRequest, ActionTarget, ChainId, ContextSlice,
};
use ioi_types::codec;
use ioi_types::error::{StateError, VmError};
use std::collections::{BTreeMap, HashMap};
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};

fn test_agent_state() -> AgentState {
    AgentState {
        session_id: [0u8; 32],
        goal: "test".to_string(),
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 8,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: vec![],
        budget: 1,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None,
        pending_tool_call: None,
        pending_tool_jcs: None,
        pending_tool_hash: None,
        pending_request_nonce: None,
        pending_visual_hash: None,
        recent_actions: vec![],
        mode: AgentMode::Agent,
        current_tier: ExecutionTier::DomHeadless,
        last_screen_phash: None,
        execution_queue: vec![],
        pending_search_completion: None,
        planner_state: None,
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
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

#[test]
fn route_contract_install_tool_emits_software_install_plan_from_structured_contract() {
    let mut state = test_agent_state();
    state.goal = "CHAT ARTIFACT ROUTE CONTRACT:\n- selected_route: install lmstudio\n- route_family: command_execution\n- output_intent: tool_execution\n- direct_answer_allowed: false\n- primary_tools: host_discovery, software_install_resolver, software_install__execute_plan, app__launch\n- software_install_target_text: lmstudio\nUSER REQUEST:\n[Codebase context]\nWorkspace: .\n\n[User request]\ninstall lmstudio".to_string();

    let tool_call =
        maybe_route_contract_local_install_tool_call(&mut state).expect("tool call should route");
    assert!(tool_call.contains("\"name\":\"software_install__execute_plan\""));
    assert!(tool_call.contains("\"plan_ref\""));
    assert!(state.recent_actions.iter().any(
        |action| action.starts_with("route_contract_tool_call:software_install__execute_plan")
    ));

    assert!(maybe_route_contract_local_install_tool_call(&mut state).is_none());
}

#[test]
fn route_contract_install_tool_does_not_parse_user_text_without_contract_target() {
    let mut state = test_agent_state();
    state.goal = "CHAT ARTIFACT ROUTE CONTRACT:\n- selected_route: install lmstudio\n- route_family: command_execution\n- output_intent: tool_execution\n- direct_answer_allowed: false\n- primary_tools: host_discovery, software_install_resolver, software_install__execute_plan, app__launch\nUSER REQUEST:\ninstall lmstudio".to_string();

    assert!(maybe_route_contract_local_install_tool_call(&mut state).is_none());
}

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl StateAccess for MockState {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        Ok(self.data.get(key).cloned())
    }

    fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), StateError> {
        self.data.remove(key);
        Ok(())
    }

    fn batch_set(&mut self, updates: &[(Vec<u8>, Vec<u8>)]) -> Result<(), StateError> {
        for (key, value) in updates {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn batch_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, StateError> {
        keys.iter().map(|key| self.get(key)).collect()
    }

    fn batch_apply(
        &mut self,
        inserts: &[(Vec<u8>, Vec<u8>)],
        deletes: &[Vec<u8>],
    ) -> Result<(), StateError> {
        for key in deletes {
            self.delete(key)?;
        }
        for (key, value) in inserts {
            self.insert(key, value)?;
        }
        Ok(())
    }

    fn prefix_scan(&self, prefix: &[u8]) -> Result<StateScanIter<'_>, StateError> {
        let rows: Vec<_> = self
            .data
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| Ok((Arc::from(key.as_slice()), Arc::from(value.as_slice()))))
            .collect();
        Ok(Box::new(rows.into_iter()))
    }
}

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
            .map_err(|error| VmError::HostError(format!("mock PNG encode failed: {error}")))?;
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

fn build_test_service() -> RuntimeAgentService {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let runtime = Arc::new(MockInferenceRuntime);
    RuntimeAgentService::new(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime,
    )
}

fn build_test_service_hybrid(
    fast_inference: Arc<dyn InferenceRuntime>,
    reasoning_inference: Arc<dyn InferenceRuntime>,
) -> RuntimeAgentService {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        fast_inference,
        reasoning_inference,
    )
}

fn install_route_contract_goal(target: &str) -> String {
    format!(
        "CHAT ARTIFACT ROUTE CONTRACT:\n\
         - selected_route: install {target}\n\
         - route_family: command_execution\n\
         - output_intent: tool_execution\n\
         - direct_answer_allowed: false\n\
         - primary_tools: host_discovery, software_install_resolver, software_install__execute_plan, app__launch\n\
         - software_install_target_text: {target}\n\
         USER REQUEST:\n\
         [Codebase context]\n\
         Workspace: .\n\n\
         [User request]\n\
         install {target}"
    )
}

#[tokio::test(flavor = "current_thread")]
async fn route_contract_install_bypasses_intent_inference_before_approval() {
    let runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This inference output should never be consumed.",
    ]));
    let memory_path = std::env::temp_dir().join(format!(
        "ioi_route_contract_install_bypass_{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |time| time.as_nanos())
    ));
    let memory_runtime =
        MemoryRuntime::open_sqlite(&memory_path).expect("memory runtime should initialize");
    let service = build_test_service_hybrid(runtime.clone(), runtime.clone())
        .with_memory_runtime(Arc::new(memory_runtime));
    let mut state = MockState::default();
    let session_id = [0x64; 32];
    let mut agent_state = test_agent_state();
    agent_state.session_id = session_id;
    agent_state.goal = install_route_contract_goal("ffmpeg");
    let key = get_state_key(&session_id);
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&agent_state).expect("agent state encodes"),
        )
        .expect("state insert succeeds");

    let services = ServiceDirectory::default();
    let mut ctx = TxContext {
        block_height: 7,
        block_timestamp: 1_750_000_000_000_000_000,
        chain_id: ChainId(0),
        signer_account_id: AccountId([9u8; 32]),
        services: &services,
        simulation: false,
        is_internal: false,
    };

    handle_step(
        &service,
        &mut state,
        StepAgentParams { session_id },
        &mut ctx,
    )
    .await
    .expect("route contract install step should process");

    assert!(runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());

    let updated: AgentState = codec::from_bytes_canonical(
        &state
            .get(&key)
            .expect("state get succeeds")
            .expect("agent state remains persisted"),
    )
    .expect("updated state decodes");
    assert!(
        matches!(
        updated.status,
        AgentStatus::Paused(ref reason)
            if reason.contains("Awaiting install approval: ffmpeg")
        ),
        "unexpected status after route-contract install handoff: status={:?} pending_tool_call={:?} queue_len={} log={:?}",
        updated.status,
        updated.pending_tool_call,
        updated.execution_queue.len(),
        updated.tool_execution_log
    );
    assert!(updated
        .pending_tool_call
        .as_deref()
        .is_some_and(|tool_call| tool_call.contains("\"plan_ref\"")));
    let _ = std::fs::remove_file(memory_path);
}

#[derive(Debug, Default)]
struct RecordingInferenceRuntime {
    outputs: Mutex<Vec<Vec<u8>>>,
    seen_inputs: Mutex<Vec<String>>,
}

impl RecordingInferenceRuntime {
    fn with_outputs<I>(outputs: I) -> Self
    where
        I: IntoIterator<Item = &'static str>,
    {
        let mut queued = outputs
            .into_iter()
            .map(|value| value.as_bytes().to_vec())
            .collect::<Vec<_>>();
        queued.reverse();
        Self {
            outputs: Mutex::new(queued),
            seen_inputs: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl InferenceRuntime for RecordingInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        self.seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .push(String::from_utf8_lossy(input_context).to_string());
        self.outputs
            .lock()
            .expect("outputs mutex poisoned")
            .pop()
            .ok_or_else(|| VmError::HostError("no mock output queued".to_string()))
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn resolved_web_intent_with_playbook(playbook_id: &str) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "web.research".to_string(),
        scope: IntentScopeProfile::WebResearch,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "intent-catalog-test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [1u8; 32],
        tool_registry_hash: [2u8; 32],
        capability_ontology_hash: [3u8; 32],
        query_normalization_version: "intent-query-norm-v1".to_string(),
        intent_catalog_source_hash: [4u8; 32],
        evidence_requirements_hash: [5u8; 32],
        provider_selection: None,
        instruction_contract: Some(InstructionContract {
            operation: "web.research".to_string(),
            side_effect_mode: Default::default(),
            slot_bindings: vec![InstructionSlotBinding {
                slot: "playbook_id".to_string(),
                binding_kind: InstructionBindingKind::UserLiteral,
                value: Some(playbook_id.to_string()),
                origin: ArgumentOrigin::default(),
                protected_slot_kind: Default::default(),
            }],
            negative_constraints: vec![],
            success_criteria: vec![],
        }),
        constrained: false,
    }
}

fn resolved_conversation_intent() -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "conversation.reply".to_string(),
        scope: IntentScopeProfile::Conversation,
        band: IntentConfidenceBand::High,
        score: 1.0,
        top_k: vec![],
        required_capabilities: vec![CapabilityId::from("conversation.reply")],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "intent-catalog-test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "v1".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [1u8; 32],
        tool_registry_hash: [2u8; 32],
        capability_ontology_hash: [3u8; 32],
        query_normalization_version: "intent-query-norm-v1".to_string(),
        intent_catalog_source_hash: [4u8; 32],
        evidence_requirements_hash: [5u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

#[test]
fn stale_canonical_pending_requires_cleanup_without_approval_or_runtime_retry() {
    let mut state = test_agent_state();
    state.pending_tool_jcs = Some(vec![1, 2, 3]);
    assert!(should_clear_stale_canonical_pending(&state, false));
}

#[test]
fn canonical_pending_is_not_stale_when_runtime_retry_is_expected() {
    let mut state = test_agent_state();
    state.pending_tool_jcs = Some(vec![1, 2, 3]);
    assert!(!should_clear_stale_canonical_pending(&state, true));
}

#[test]
fn retry_blocked_pause_auto_resumes_and_clears_recent_actions() {
    let mut state = test_agent_state();
    state.status =
        AgentStatus::Paused("Retry blocked: unchanged AttemptKey for UnexpectedState".to_string());
    state.recent_actions = vec!["file__read".to_string()];

    ensure_agent_running_or_resume_retry_pause(&mut state).expect("retry pause should resume");

    assert_eq!(state.status, AgentStatus::Running);
    assert!(state.recent_actions.is_empty());
}

#[test]
fn non_retry_pause_is_rejected_by_step_resumption_gate() {
    let mut state = test_agent_state();
    state.status = AgentStatus::Paused("Waiting for human approval".to_string());

    let error = ensure_agent_running_or_resume_retry_pause(&mut state)
        .expect_err("non-retry pause should not auto-resume");

    assert!(error
        .to_string()
        .contains("Agent not running: Paused(\"Waiting for human approval\")"));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_generates_chat_reply_for_conversation_route() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "The Pythagorean theorem states that in a right triangle, a^2 + b^2 = c^2.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x61; 32];
    agent_state.goal = "What is the Pythagorean theorem?".to_string();
    agent_state.resolved_intent = Some(resolved_conversation_intent());

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("direct inline authoring should succeed");

    let tool_call = tool_call.expect("conversation route should synthesize chat reply");
    let payload: serde_json::Value =
        serde_json::from_str(&tool_call).expect("tool call should decode");
    assert_eq!(
        payload.get("name").and_then(|value| value.as_str()),
        Some("chat__reply")
    );
    assert_eq!(
        payload
            .get("arguments")
            .and_then(|arguments| arguments.get("message"))
            .and_then(|value| value.as_str()),
        Some("The Pythagorean theorem states that in a right triangle, a^2 + b^2 = c^2.")
    );

    let seen_inputs = fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned");
    assert_eq!(seen_inputs.len(), 1);
    assert!(seen_inputs[0].contains("Return ONLY the final user-facing answer text."));
    assert!(seen_inputs[0].contains("What is the Pythagorean theorem?"));
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_skips_research_routes() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This should never be used.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x62; 32];
    agent_state.goal = "What is the weather in Boston today?".to_string();
    agent_state.resolved_intent =
        Some(resolved_web_intent_with_playbook("citation_grounded_brief"));

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("research route should evaluate");

    assert!(tool_call.is_none());
    assert!(fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn direct_inline_authoring_skips_delegation_routes() {
    let fast_runtime = Arc::new(RecordingInferenceRuntime::with_outputs([
        "This should never be used.",
    ]));
    let service = build_test_service_hybrid(fast_runtime.clone(), fast_runtime.clone());
    let state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x63; 32];
    agent_state.goal = "Wait for the child worker result".to_string();
    let mut intent = resolved_conversation_intent();
    intent.intent_id = "delegation.task".to_string();
    intent.scope = IntentScopeProfile::Delegation;
    intent.required_capabilities = vec![
        CapabilityId::from("agent.lifecycle"),
        CapabilityId::from("delegation.manage"),
    ];
    agent_state.resolved_intent = Some(intent);

    let tool_call = maybe_direct_inline_author_tool_call(
        &service,
        &state,
        &agent_state,
        agent_state.session_id,
        ExecutionTier::DomHeadless,
    )
    .await
    .expect("delegation route should evaluate");

    assert!(tool_call.is_none());
    assert!(fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn optimizer_recovery_is_skipped_without_optimizer_configuration() {
    let service = build_test_service();
    let mut state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = [0x44; 32];
    agent_state.consecutive_failures = 3;
    let session_id = agent_state.session_id;
    let key = get_state_key(&session_id);

    let triggered =
        maybe_run_optimizer_recovery(&service, &mut state, &mut agent_state, session_id, &key, 7)
            .await
            .expect("optimizer gate should evaluate");

    assert!(!triggered);
    assert_eq!(agent_state.consecutive_failures, 3);
    assert!(agent_state.active_skill_hash.is_none());
}

#[test]
fn root_playbook_delegate_is_queued_without_cognition() {
    let session_id = [6u8; 32];
    let playbook_id = "citation_grounded_brief";
    let mut state = MockState::default();
    let mut agent_state = test_agent_state();
    agent_state.session_id = session_id;
    agent_state.goal = "Research the latest NIST PQC standards.".to_string();
    agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));

    let queued = queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
        .expect("queue delegate request");

    assert!(queued);
    assert_eq!(agent_state.execution_queue.len(), 1);
    assert_eq!(
        agent_state.execution_queue[0].target,
        ActionTarget::Custom("agent__delegate".to_string())
    );
    let args: serde_json::Value = serde_json::from_slice(&agent_state.execution_queue[0].params)
        .expect("delegate params should decode");
    assert_eq!(
        args.get("goal").and_then(|value| value.as_str()),
        Some("Research the latest NIST PQC standards.")
    );
    assert_eq!(
        args.get("playbook_id").and_then(|value| value.as_str()),
        Some(playbook_id)
    );

    let run = ParentPlaybookRun {
        parent_session_id: session_id,
        playbook_id: playbook_id.to_string(),
        playbook_label: "Citation-Grounded Brief".to_string(),
        topic: "latest NIST PQC standards".to_string(),
        status: ParentPlaybookStatus::Running,
        current_step_index: 0,
        active_child_session_id: Some([9u8; 32]),
        started_at_ms: 1,
        updated_at_ms: 1,
        completed_at_ms: None,
        steps: vec![],
    };
    state
        .insert(
            &get_parent_playbook_run_key(&session_id, playbook_id),
            &codec::to_bytes_canonical(&run).expect("playbook bytes"),
        )
        .expect("persist playbook run");
    agent_state.execution_queue.clear();

    let queued_again = queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
        .expect("queue delegate request after kickoff");

    assert!(!queued_again);
    assert!(agent_state.execution_queue.is_empty());
    state
        .delete(&get_parent_playbook_run_key(&session_id, playbook_id))
        .expect("delete playbook run");

    let child_session_id = [10u8; 32];
    let mut child_state = test_agent_state();
    child_state.session_id = child_session_id;
    child_state.parent_session_id = Some(session_id);
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist child state");
    agent_state.child_session_ids.push(child_session_id);

    let queued_with_child =
        queue_root_playbook_delegate_request(&state, &mut agent_state, session_id)
            .expect("queue delegate request after child spawn");

    assert!(!queued_with_child);
    assert!(agent_state.execution_queue.is_empty());
}

#[test]
fn active_parent_playbook_child_gets_single_startup_await_without_cognition() {
    let session_id = [7u8; 32];
    let child_session_id = [8u8; 32];
    let playbook_id = "citation_grounded_brief";
    let mut state = MockState::default();
    let run = ParentPlaybookRun {
        parent_session_id: session_id,
        playbook_id: playbook_id.to_string(),
        playbook_label: "Citation-Grounded Brief".to_string(),
        topic: "latest NIST PQC standards".to_string(),
        status: ParentPlaybookStatus::Running,
        current_step_index: 0,
        active_child_session_id: Some(child_session_id),
        started_at_ms: 1,
        updated_at_ms: 1,
        completed_at_ms: None,
        steps: vec![],
    };
    state
        .insert(
            &get_parent_playbook_run_key(&session_id, playbook_id),
            &codec::to_bytes_canonical(&run).expect("playbook bytes"),
        )
        .expect("persist playbook run");

    let mut agent_state = test_agent_state();
    agent_state.session_id = session_id;
    agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));
    let mut child_state = test_agent_state();
    child_state.session_id = child_session_id;
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist child state");

    let queued = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request");

    assert!(queued);
    assert_eq!(agent_state.execution_queue.len(), 1);
    assert_eq!(
        agent_state.execution_queue[0].target,
        ActionTarget::Custom("agent__await".to_string())
    );
    let args: serde_json::Value = serde_json::from_slice(&agent_state.execution_queue[0].params)
        .expect("await params should decode");
    assert_eq!(
        args.get("child_session_id_hex")
            .and_then(|value| value.as_str()),
        Some(hex::encode(child_session_id).as_str())
    );

    child_state.step_count = 1;
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist updated child state");
    agent_state.execution_queue.clear();

    let queued_again = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request after child start");

    assert!(queued_again);
    assert_eq!(agent_state.execution_queue.len(), 1);
    agent_state.execution_queue.clear();

    child_state.status = AgentStatus::Completed(Some(
        "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)"
            .to_string(),
    ));
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist completed child state");

    let queued_terminal = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request after child completion");

    assert!(queued_terminal);
    assert_eq!(agent_state.execution_queue.len(), 1);
    agent_state.execution_queue.clear();
    child_state.status = AgentStatus::Running;
    child_state.pending_tool_call =
        Some("{\"name\":\"agent__complete\",\"arguments\":{\"result\":\"done\"}}".to_string());
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist pending child state");

    let queued_pending = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request after child pending tool");

    assert!(queued_pending);
    assert_eq!(agent_state.execution_queue.len(), 1);
    agent_state.execution_queue.clear();
    child_state.pending_tool_call = None;

    child_state.execution_queue.push(ActionRequest {
        target: ActionTarget::Custom("web__read".to_string()),
        params: serde_jcs::to_vec(&serde_json::json!({
            "url": "https://csrc.nist.gov/projects/post-quantum-cryptography"
        }))
        .expect("queued child params"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(child_session_id),
            window_id: None,
        },
        nonce: 1,
    });
    state
        .insert(
            &get_state_key(&child_session_id),
            &codec::to_bytes_canonical(&child_state).expect("child bytes"),
        )
        .expect("persist queued child state");

    let queued_followup = queue_parent_playbook_await_request(&state, &mut agent_state, session_id)
        .expect("queue await request for queued child follow-up");

    assert!(queued_followup);
    assert_eq!(agent_state.execution_queue.len(), 1);
    state
        .delete(&get_parent_playbook_run_key(&session_id, playbook_id))
        .expect("delete playbook run");

    let fallback_child_session_id = [9u8; 32];
    let mut fallback_agent_state = test_agent_state();
    fallback_agent_state.session_id = session_id;
    fallback_agent_state.resolved_intent = Some(resolved_web_intent_with_playbook(playbook_id));
    fallback_agent_state
        .child_session_ids
        .push(fallback_child_session_id);
    let mut fallback_child_state = test_agent_state();
    fallback_child_state.session_id = fallback_child_session_id;
    fallback_child_state.parent_session_id = Some(session_id);
    state
        .insert(
            &get_state_key(&fallback_child_session_id),
            &codec::to_bytes_canonical(&fallback_child_state).expect("fallback child bytes"),
        )
        .expect("persist fallback child state");

    let fallback_queued =
        queue_parent_playbook_await_request(&state, &mut fallback_agent_state, session_id)
            .expect("queue await request from child fallback");

    assert!(fallback_queued);
    assert_eq!(fallback_agent_state.execution_queue.len(), 1);
    let fallback_args: serde_json::Value =
        serde_json::from_slice(&fallback_agent_state.execution_queue[0].params)
            .expect("fallback await params should decode");
    assert_eq!(
        fallback_args
            .get("child_session_id_hex")
            .and_then(|value| value.as_str()),
        Some(hex::encode(fallback_child_session_id).as_str())
    );
}
