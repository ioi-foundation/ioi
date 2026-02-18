// Path: crates/cli/tests/agent_resilience_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::Result;
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::InferenceRuntime;
use ioi_cli::testing::build_test_artifacts;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::keys::AGENT_POLICY_PREFIX;
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::types::PostMessageParams;
use ioi_services::agentic::desktop::{
    AgentMode, AgentState, AgentStatus, DesktopAgentService, StartAgentParams, StepAgentParams,
};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::agentic::{IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState};
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent};
use ioi_types::{codec, error::VmError};
use serde_json::json;
use std::io::Cursor;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::broadcast;

use image::{ImageBuffer, ImageFormat, Rgba};

static WEB_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct ScopedEnvVar {
    key: &'static str,
    previous: Option<String>,
}

impl ScopedEnvVar {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        if let Some(prev) = &self.previous {
            std::env::set_var(self.key, prev);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[derive(Clone)]
struct MockGuiDriver {
    fail_count: Arc<Mutex<u32>>,
}

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
        Ok(String::new())
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
        let mut count = self.fail_count.lock().unwrap();
        if *count < 2 {
            *count += 1;
            return Err(VmError::HostError("Click drifted".into()));
        }
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

struct ResilientBrain;

#[async_trait]
impl InferenceRuntime for ResilientBrain {
    async fn execute_inference(
        &self,
        _hash: [u8; 32],
        _input: &[u8],
        _opts: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let tool_call = json!({
            "name": "gui__click",
            "arguments": { "x": 100, "y": 100, "button": "left" }
        });
        Ok(tool_call.to_string().into_bytes())
    }

    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

struct WebTimeoutBrain;

#[async_trait]
impl InferenceRuntime for WebTimeoutBrain {
    async fn execute_inference(
        &self,
        _hash: [u8; 32],
        _input: &[u8],
        _opts: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        let tool_call = json!({
            "name": "web__search",
            "arguments": { "query": "latest news", "limit": 5 }
        });
        Ok(tool_call.to_string().into_bytes())
    }

    async fn load_model(&self, _: [u8; 32], _: &Path) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _: [u8; 32]) -> Result<(), VmError> {
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

fn read_agent_state(state: &IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) -> AgentState {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    codec::from_bytes_canonical(&bytes).expect("agent state should decode")
}

fn seed_resolved_intent(
    state: &mut IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
    scope: IntentScopeProfile,
) {
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)
        .expect("state get should not fail")
        .expect("session state should exist");
    let mut agent_state: AgentState =
        codec::from_bytes_canonical(&bytes).expect("agent state should decode");
    agent_state.resolved_intent = Some(ResolvedIntentState {
        intent_id: match scope {
            IntentScopeProfile::WebResearch => "web.research".to_string(),
            IntentScopeProfile::UiInteraction => "ui.interaction".to_string(),
            _ => "unknown".to_string(),
        },
        scope,
        band: IntentConfidenceBand::High,
        score: 0.99,
        top_k: vec![],
        preferred_tier: "tool_first".to_string(),
        matrix_version: "test".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        constrained: false,
    });
    agent_state.awaiting_intent_clarification = false;
    agent_state.status = AgentStatus::Running;
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&agent_state).expect("state encode"),
        )
        .expect("state insert should not fail");
}

fn enable_intent_shadow_mode(state: &mut IAVLTree<HashCommitmentScheme>, session_id: [u8; 32]) {
    let mut rules = default_safe_policy();
    rules.ontology_policy.intent_routing.shadow_mode = true;
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state
        .insert(
            &policy_key,
            &codec::to_bytes_canonical(&rules).expect("policy encode"),
        )
        .expect("policy insert should not fail");
}

fn build_scs() -> Result<(SovereignContextStore, tempfile::TempDir)> {
    let temp_dir = tempdir()?;
    let scs_path = temp_dir.path().join("resilience.scs");
    let scs = SovereignContextStore::create(
        &scs_path,
        StoreConfig {
            chain_id: 1,
            owner_id: [0u8; 32],
            identity_key: [0x11; 32],
        },
    )?;
    Ok((scs, temp_dir))
}

#[tokio::test(flavor = "multi_thread")]
async fn test_agent_self_healing() -> Result<()> {
    build_test_artifacts();

    let gui = Arc::new(MockGuiDriver {
        fail_count: Arc::new(Mutex::new(0)),
    });
    let brain = Arc::new(ResilientBrain);
    let (scs, _scs_tmp_dir) = build_scs()?;

    let service = DesktopAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        brain.clone(),
        brain.clone(),
    )
    .with_scs(Arc::new(Mutex::new(scs)));
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);

    let session_id = [1u8; 32];
    let start_params = StartAgentParams {
        session_id,
        goal: "Click".into(),
        max_steps: 5,
        parent_session_id: None,
        initial_budget: 1000,
        mode: AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).unwrap(),
            &mut ctx,
        )
        .await?;
    enable_intent_shadow_mode(&mut state, session_id);
    seed_resolved_intent(&mut state, session_id, IntentScopeProfile::UiInteraction);

    let step_params = StepAgentParams { session_id };
    let step_bytes = codec::to_bytes_canonical(&step_params).unwrap();

    for _ in 0..3 {
        service
            .handle_service_call(&mut state, "step@v1", &step_bytes, &mut ctx)
            .await?;
    }

    let final_state = read_agent_state(&state, session_id);
    assert!(final_state.step_count >= 1);
    assert!(
        !matches!(final_state.status, AgentStatus::Failed(_)),
        "agent should not hard-fail in resilience smoke path"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "Requires deterministic intent/execution fixture for stable timeout fail-fast assertions"]
async fn latest_news_timeout_fails_fast_without_remedy_churn() -> Result<()> {
    build_test_artifacts();

    let _lock = WEB_ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock");
    let _force_browser_timeout = ScopedEnvVar::set("IOI_WEB_TEST_FORCE_BROWSER_TIMEOUT", "1");
    let _force_http_timeout = ScopedEnvVar::set("IOI_WEB_TEST_FORCE_HTTP_TIMEOUT", "1");

    let (event_tx, mut event_rx) = broadcast::channel(256);
    let gui = Arc::new(MockGuiDriver {
        fail_count: Arc::new(Mutex::new(0)),
    });
    let brain = Arc::new(WebTimeoutBrain);
    let (scs, _scs_tmp_dir) = build_scs()?;

    let service = DesktopAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        brain.clone(),
        brain.clone(),
    )
    .with_scs(Arc::new(Mutex::new(scs)))
    .with_event_sender(event_tx);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = [9u8; 32];

    let start_params = StartAgentParams {
        session_id,
        goal: "search latest news and summarize".into(),
        max_steps: 12,
        parent_session_id: None,
        initial_budget: 1000,
        mode: AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params).unwrap(),
            &mut ctx,
        )
        .await?;
    enable_intent_shadow_mode(&mut state, session_id);
    seed_resolved_intent(&mut state, session_id, IntentScopeProfile::WebResearch);

    let started = Instant::now();
    let mut final_state = read_agent_state(&state, session_id);
    for _ in 0..8 {
        final_state = read_agent_state(&state, session_id);
        if matches!(final_state.status, AgentStatus::Completed(_)) {
            break;
        }
        if matches!(final_state.status, AgentStatus::Failed(_)) {
            break;
        }
        if matches!(final_state.status, AgentStatus::Paused(_)) {
            let clarify = PostMessageParams {
                session_id,
                role: "user".to_string(),
                content: "search latest news and summarize".to_string(),
            };
            service
                .handle_service_call(
                    &mut state,
                    "post_message@v1",
                    &codec::to_bytes_canonical(&clarify).unwrap(),
                    &mut ctx,
                )
                .await?;
            final_state = read_agent_state(&state, session_id);
            if !matches!(final_state.status, AgentStatus::Running) {
                continue;
            }
        }
        if !matches!(final_state.status, AgentStatus::Running) {
            break;
        }

        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id }).unwrap(),
                &mut ctx,
            )
            .await?;
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_secs() <= 90,
        "timeout path should terminate within 90s, got {:?}",
        elapsed
    );

    final_state = read_agent_state(&state, session_id);
    assert!(final_state.step_count <= 8);

    let mut saw_timeout_fail_fast = false;
    let mut saw_timeout_failure_class = false;
    let mut saw_filesystem_list_directory = false;
    let mut saw_max_steps = false;

    while let Ok(event) = event_rx.try_recv() {
        match event {
            KernelEvent::RoutingReceipt(receipt) => {
                if receipt.tool_name == "filesystem__list_directory" {
                    saw_filesystem_list_directory = true;
                }
                if receipt
                    .post_state
                    .verification_checks
                    .iter()
                    .any(|check| check == "web_timeout_fail_fast=true")
                {
                    saw_timeout_fail_fast = true;
                }
                if receipt.failure_class_name == "TimeoutOrHang" {
                    saw_timeout_failure_class = true;
                }
            }
            KernelEvent::AgentActionResult { tool_name, .. } => {
                if tool_name == "filesystem__list_directory" {
                    saw_filesystem_list_directory = true;
                }
                if tool_name == "system::max_steps_reached" {
                    saw_max_steps = true;
                }
            }
            _ => {}
        }
    }

    assert!(
        saw_timeout_fail_fast,
        "missing web_timeout_fail_fast marker (final_status={:?})",
        final_state.status
    );
    assert!(
        saw_timeout_failure_class,
        "expected TimeoutOrHang routing failure class"
    );
    assert!(
        !saw_filesystem_list_directory,
        "unexpected filesystem remediation churn observed"
    );
    assert!(
        !saw_max_steps,
        "timeout scenario should not terminate via max-steps budget"
    );

    Ok(())
}
