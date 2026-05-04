use super::{discover_adapter_tools, execute_dynamic_tool};
use crate::agentic::runtime::service::{RuntimeAgentService, ServiceCallContext};
use crate::agentic::runtime::types::{AgentMode, AgentState, AgentStatus, ExecutionTier};
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::{service_namespace_prefix, StateAccess};
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::ResolvedIntentState;
use ioi_types::app::{
    AccountId, ChainId, ContextSlice, KernelEvent, RuntimeTarget, WorkloadReceipt, WorkloadSpec,
};
use ioi_types::codec;
use ioi_types::error::{TransactionError, VmError};
use ioi_types::keys::active_service_key;
use ioi_types::service_configs::{ActiveServiceMeta, Capabilities, MethodPermission};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

#[derive(Clone)]
struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(1, 1);
        img.put_pixel(0, 0, Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("mock PNG encode failed: {}", e)))?;
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
        _som_map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

struct MockService;

#[async_trait]
impl BlockchainService for MockService {
    fn id(&self) -> &str {
        "mock_service"
    }

    fn abi_version(&self) -> u32 {
        1
    }

    fn state_schema(&self) -> &str {
        "mock.v1"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::empty()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn handle_service_call(
        &self,
        state: &mut dyn StateAccess,
        method: &str,
        params: &[u8],
        _ctx: &mut ioi_api::transaction::context::TxContext<'_>,
    ) -> Result<(), TransactionError> {
        state
            .insert(
                b"last_call",
                format!("{}:{}", method, String::from_utf8_lossy(params)).as_bytes(),
            )
            .map_err(TransactionError::State)?;
        Ok(())
    }
}

fn mock_service_meta() -> ActiveServiceMeta {
    let mut methods = BTreeMap::new();
    methods.insert("ping@v1".to_string(), MethodPermission::User);
    ActiveServiceMeta {
        id: "mock_service".to_string(),
        abi_version: 1,
        state_schema: "mock.v1".to_string(),
        caps: Capabilities::empty(),
        artifact_hash: [0u8; 32],
        activated_at: 0,
        methods,
        allowed_system_prefixes: vec![],
        generation_id: 0,
        parent_hash: None,
        author: None,
        context_filter: None,
    }
}

fn agent_state() -> AgentState {
    AgentState {
        session_id: [0x11; 32],
        goal: "test".to_string(),
        runtime_route_frame: None,
        transcript_root: [0u8; 32],
        status: AgentStatus::Running,
        step_count: 0,
        max_steps: 4,
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
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: None::<ResolvedIntentState>,
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        active_lens: None,
        pending_search_completion: None,
        planner_state: None,
        command_history: Default::default(),
    }
}

#[tokio::test]
async fn discover_adapter_tools_includes_google_and_service_tools() {
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    state
        .insert(
            &active_service_key("mock_service"),
            &codec::to_bytes_canonical(&mock_service_meta()).expect("encode service meta"),
        )
        .expect("insert service meta");

    let (tools, names) = discover_adapter_tools(&state, None, "Autopilot Chat", None).await;
    assert!(names.contains("connector__google__gmail_read_emails"));
    assert!(names.contains("mock_service__ping"));
    assert!(
        tools
            .iter()
            .any(|tool| tool.name == "connector__google__gmail_read_emails"),
        "google connector tools should flow through adapter discovery"
    );
}

#[tokio::test]
async fn generic_service_adapter_executes_and_emits_adapter_receipt() {
    let runtime = Arc::new(MockInferenceRuntime);
    let (sender, mut receiver) = tokio::sync::broadcast::channel::<KernelEvent>(16);
    let service = RuntimeAgentService::new_hybrid(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime,
    )
    .with_event_sender(sender);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    state
        .insert(
            &active_service_key("mock_service"),
            &codec::to_bytes_canonical(&mock_service_meta()).expect("encode service meta"),
        )
        .expect("insert service meta");

    let services = ServiceDirectory::new(vec![Arc::new(MockService)]);
    let call_context = ServiceCallContext {
        block_height: 1,
        block_timestamp: 1,
        chain_id: ChainId(1),
        signer_account_id: AccountId::default(),
        services: &services,
        simulation: false,
        is_internal: false,
    };
    let outcome = execute_dynamic_tool(
        &service,
        &json!({
            "name": "mock_service__ping",
            "arguments": { "params": "{\"ping\":true}" }
        }),
        [0x44; 32],
        7,
        &WorkloadSpec {
            runtime_target: RuntimeTarget::Adapter,
            net_mode: ioi_types::app::NetMode::Disabled,
            capability_lease: None,
            ui_surface: None,
        },
        &agent_state(),
        Some(&mut state),
        Some(call_context),
        None,
    )
    .await
    .expect("adapter execution should succeed")
    .expect("adapter outcome should be present");

    assert!(outcome.success);
    let mut last_call_key = service_namespace_prefix("mock_service");
    last_call_key.extend_from_slice(b"last_call");
    let service_value = state
        .get(&last_call_key)
        .expect("state get should succeed")
        .expect("service side effect should be stored");
    assert_eq!(
        String::from_utf8(service_value).expect("utf8 state"),
        "ping@v1:{\"ping\":true}"
    );

    let mut saw_adapter_receipt = false;
    while let Ok(event) = receiver.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            if let WorkloadReceipt::Adapter(receipt) = receipt_event.receipt {
                saw_adapter_receipt = true;
                assert_eq!(receipt.adapter_id, "service::mock_service");
                assert_eq!(receipt.tool_name, "mock_service__ping");
                assert!(receipt.success);
            }
        }
    }
    assert!(saw_adapter_receipt, "adapter receipt should be emitted");
}
