use anyhow::Result;
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::keys::{get_state_key, AGENT_POLICY_PREFIX};
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::{AgentMode, AgentState, AgentStatus, DesktopAgentService};
use ioi_services::agentic::desktop::{StartAgentParams, StepAgentParams};
use ioi_services::agentic::rules::{Rule, Verdict};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{InferenceOptions, IntentAmbiguityAction};
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent};
use ioi_types::codec;
use ioi_types::error::VmError;
use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let mut bytes: Vec<u8> = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), ImageFormat::Png)
            .map_err(|e| VmError::HostError(format!("Mock PNG encoding failed: {}", e)))?;
        Ok(bytes)
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        self.capture_screen(None).await
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Ok("<root/>".to_string())
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
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

#[derive(Clone)]
struct NoopOsDriver;

#[async_trait]
impl OsDriver for NoopOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(Some("UnitTest Window".to_string()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(Some(WindowInfo {
            title: "UnitTest Window".to_string(),
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            app_name: "UnitTest".to_string(),
        }))
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(false)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

#[derive(Debug, Default, Clone)]
struct TimerIntentRuntime;

#[async_trait]
impl InferenceRuntime for TimerIntentRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(br#"{"name":"chat__reply","arguments":{"text":"noop"}}"#.to_vec())
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let text_lc = text.to_ascii_lowercase();
        if text_lc.contains("timer") || text_lc.contains("countdown") {
            return Ok(vec![1.0, 0.0, 0.0]);
        }
        if text_lc.contains("clock") || text_lc.contains("timestamp") {
            return Ok(vec![0.0, 1.0, 0.0]);
        }
        Ok(vec![0.0, 0.0, 1.0])
    }

    async fn load_model(&self, _model_hash: [u8; 32], _path: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_ctx<'a>(services: &'a ServiceDirectory) -> TxContext<'a> {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    TxContext {
        block_height: 1,
        block_timestamp: now_ns,
        chain_id: ioi_types::app::ChainId(0),
        signer_account_id: ioi_types::app::AccountId::default(),
        services,
        simulation: false,
        is_internal: false,
    }
}

fn read_agent_state(
    state: &IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
) -> Result<AgentState> {
    let key = get_state_key(&session_id);
    let bytes = state
        .get(&key)?
        .ok_or_else(|| anyhow::anyhow!("session state not found"))?;
    codec::from_bytes_canonical(&bytes).map_err(anyhow::Error::msg)
}

#[tokio::test(flavor = "multi_thread")]
async fn timer_query_runs_planner_worker_live_path() -> Result<()> {
    let (tx, mut rx) = tokio::sync::broadcast::channel(256);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let scs_path = std::env::temp_dir().join(format!("timer_planner_live_e2e_{}.scs", now_ns));
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x22; 32],
        },
    )?;
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(TimerIntentRuntime);
    let service = DesktopAgentService::new_hybrid(gui, terminal, browser, runtime.clone(), runtime)
        .with_scs(Arc::new(Mutex::new(scs)))
        .with_event_sender(tx)
        .with_os_driver(Arc::new(NoopOsDriver));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);

    let session_id = [0xAB; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Set a timer for 15 minutes".to_string(),
        max_steps: 8,
        parent_session_id: None,
        initial_budget: 1000,
        mode: AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).map_err(anyhow::Error::msg)?,
            &mut ctx,
        )
        .await?;

    let mut rules = default_safe_policy();
    rules.rules.push(Rule {
        rule_id: Some("allow-timer-manage-e2e".to_string()),
        target: "timer::manage".to_string(),
        conditions: Default::default(),
        action: Verdict::Allow,
    });
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state.insert(
        &policy_key,
        &codec::to_bytes_canonical(&rules).map_err(anyhow::Error::msg)?,
    )?;

    while rx.try_recv().is_ok() {}

    service
        .handle_service_call(
            &mut state,
            "step@v1",
            &codec::to_bytes_canonical(&StepAgentParams { session_id })
                .map_err(anyhow::Error::msg)?,
            &mut ctx,
        )
        .await?;

    let mut events = Vec::<KernelEvent>::new();
    let deadline = tokio::time::Instant::now() + Duration::from_millis(200);
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => events.push(event),
            _ => break,
        }
    }

    let agent_state = read_agent_state(&state, session_id)?;
    let resolved = agent_state
        .resolved_intent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("resolved intent missing"))?;
    assert_eq!(resolved.intent_id, "timer.manage");
    assert_ne!(resolved.intent_id, "system.clock.read");

    let final_message = match &agent_state.status {
        AgentStatus::Completed(Some(output)) => output.clone(),
        other => return Err(anyhow::anyhow!("unexpected final status: {:?}", other)),
    };
    assert!(
        final_message.contains("Route: runtime.timer_toolchain"),
        "final message missing executed route: {}",
        final_message
    );
    assert!(
        final_message.contains("Target UTC:"),
        "final message missing absolute timestamp: {}",
        final_message
    );

    let mut intent_receipt_found = false;
    let mut first_plan_index: Option<usize> = None;
    let mut last_plan_index: Option<usize> = None;
    let mut first_plan_route: Option<String> = None;
    let mut last_plan_route: Option<String> = None;
    let mut planner_result_index: Option<usize> = None;
    let mut plan_hashes = Vec::<[u8; 32]>::new();

    for (idx, event) in events.iter().enumerate() {
        match event {
            KernelEvent::IntentResolutionReceipt(receipt) => {
                if receipt.session_id == Some(session_id) && receipt.intent_id == "timer.manage" {
                    intent_receipt_found = true;
                }
            }
            KernelEvent::PlanReceipt(receipt) => {
                if receipt.session_id == Some(session_id) {
                    if first_plan_index.is_none() {
                        first_plan_index = Some(idx);
                        first_plan_route = Some(receipt.selected_route.clone());
                    }
                    last_plan_index = Some(idx);
                    last_plan_route = Some(receipt.selected_route.clone());
                    plan_hashes.push(receipt.plan_hash);
                }
            }
            KernelEvent::AgentActionResult {
                session_id: event_session_id,
                tool_name,
                ..
            } => {
                if *event_session_id == session_id && tool_name == "planner::execute" {
                    planner_result_index = Some(idx);
                }
            }
            _ => {}
        }
    }

    assert!(
        intent_receipt_found,
        "expected timer.manage intent receipt in emitted events"
    );

    let first_plan_idx = first_plan_index.ok_or_else(|| anyhow::anyhow!("missing plan receipt"))?;
    let last_plan_idx =
        last_plan_index.ok_or_else(|| anyhow::anyhow!("missing final plan receipt"))?;
    assert!(
        first_plan_idx < last_plan_idx,
        "expected multiple ordered plan receipts"
    );
    assert_eq!(
        first_plan_route.as_deref(),
        Some("route.pending_host_inspection")
    );
    assert_eq!(last_plan_route.as_deref(), Some("runtime.timer_toolchain"));
    assert!(
        plan_hashes.windows(2).all(|pair| pair[0] == pair[1]),
        "expected stable plan hash across receipts"
    );

    let planner_result_idx = planner_result_index
        .ok_or_else(|| anyhow::anyhow!("missing planner::execute result event"))?;
    assert!(
        first_plan_idx < planner_result_idx,
        "expected plan receipt before planner action result event"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live external inference required for timer planner smoke test"]
async fn timer_query_live_inference_smoke() -> Result<()> {
    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow::anyhow!("OPENAI_API_KEY required for live smoke test"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());
    let api_url = "https://api.openai.com/v1/chat/completions".to_string();
    let runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url,
        openai_api_key,
        openai_model,
    ));

    let (tx, mut rx) = tokio::sync::broadcast::channel(512);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let scs_path = std::env::temp_dir().join(format!("timer_planner_live_smoke_{}.scs", now_ns));
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x33; 32],
        },
    )?;

    let service = DesktopAgentService::new_hybrid(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime,
    )
    .with_scs(Arc::new(Mutex::new(scs)))
    .with_event_sender(tx)
    .with_os_driver(Arc::new(NoopOsDriver));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = [0xCD; 32];

    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&StartAgentParams {
                session_id,
                goal: "Set a timer for 15 minutes".to_string(),
                max_steps: 10,
                parent_session_id: None,
                initial_budget: 1600,
                mode: AgentMode::Agent,
            })
            .map_err(anyhow::Error::msg)?,
            &mut ctx,
        )
        .await?;

    let mut rules = default_safe_policy();
    rules.rules.push(Rule {
        rule_id: Some("allow-timer-manage-live-smoke".to_string()),
        target: "timer::manage".to_string(),
        conditions: Default::default(),
        action: Verdict::Allow,
    });
    rules
        .ontology_policy
        .intent_routing
        .ambiguity
        .low_confidence_action = IntentAmbiguityAction::Proceed;
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state.insert(
        &policy_key,
        &codec::to_bytes_canonical(&rules).map_err(anyhow::Error::msg)?,
    )?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut events = Vec::<KernelEvent>::new();
    while tokio::time::Instant::now() < deadline {
        while let Ok(event) = rx.try_recv() {
            events.push(event);
        }
        let agent_state = read_agent_state(&state, session_id)?;
        match &agent_state.status {
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => break,
            AgentStatus::Paused(reason) => {
                return Err(anyhow::anyhow!(
                    "live smoke paused unexpectedly: {}",
                    reason
                ));
            }
            AgentStatus::Running | AgentStatus::Idle | AgentStatus::Terminated => {}
        }
        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(anyhow::Error::msg)?,
                &mut ctx,
            )
            .await?;
    }
    while let Ok(event) = rx.try_recv() {
        events.push(event);
    }

    let agent_state = read_agent_state(&state, session_id)?;
    let final_message = match &agent_state.status {
        AgentStatus::Completed(Some(text)) => text.clone(),
        AgentStatus::Completed(None) => {
            return Err(anyhow::anyhow!(
                "live smoke completed without terminal output"
            ))
        }
        other => return Err(anyhow::anyhow!("live smoke did not complete: {:?}", other)),
    };

    let resolved = agent_state
        .resolved_intent
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("resolved intent missing in live smoke"))?;
    assert_eq!(resolved.intent_id, "timer.manage");
    assert!(
        final_message.contains("Route:"),
        "missing route in final output: {}",
        final_message
    );
    assert!(
        final_message.contains("Target UTC:"),
        "missing absolute target time in final output: {}",
        final_message
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            KernelEvent::PlanReceipt(receipt) if receipt.session_id == Some(session_id)
        )),
        "live smoke expected at least one plan receipt event"
    );

    Ok(())
}
