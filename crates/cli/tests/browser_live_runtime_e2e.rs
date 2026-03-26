#[path = "live_inference_support.rs"]
mod live_inference_support;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use image::{ImageBuffer, ImageFormat, Rgba};
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::MemoryRuntime;
use ioi_services::agentic::desktop::keys::{AGENT_POLICY_PREFIX, INCIDENT_PREFIX};
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::service::step::incident::IncidentState;
use ioi_services::agentic::desktop::{
    AgentMode, AgentState, AgentStatus, DesktopAgentService, ResumeAgentParams, StartAgentParams,
    StepAgentParams,
};
use ioi_services::agentic::rules::DefaultPolicy;
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::action::{ApprovalScope, ApprovalToken};
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent, SignatureSuite};
use ioi_types::codec;
use ioi_types::error::VmError;
use serde_json::json;
use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::broadcast;

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
            .map_err(|e| VmError::HostError(format!("mock png encoding failed: {}", e)))?;
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
        Ok(Some("Browser Runtime Smoke".to_string()))
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(Some(WindowInfo {
            title: "Browser Runtime Smoke".to_string(),
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            app_name: "Chromium".to_string(),
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
    let key = [b"agent::state::".as_slice(), session_id.as_slice()].concat();
    let bytes = state
        .get(&key)?
        .ok_or_else(|| anyhow!("session state missing for {:?}", session_id))?;
    codec::from_bytes_canonical(&bytes).map_err(anyhow::Error::msg)
}

fn apply_allow_all_policy(
    state: &mut IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
) -> Result<()> {
    let mut rules = default_safe_policy();
    rules.defaults = DefaultPolicy::AllowAll;
    let policy_key = [AGENT_POLICY_PREFIX, session_id.as_slice()].concat();
    state.insert(
        &policy_key,
        &codec::to_bytes_canonical(&rules).map_err(anyhow::Error::msg)?,
    )?;
    Ok(())
}

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, sink: &mut Vec<String>) {
    while let Ok(event) = rx.try_recv() {
        sink.push(format!("{:?}", event));
    }
}

fn artifact_root() -> Result<PathBuf> {
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/browser_live_runtime")
        .join(format!("run-{}", run_id));
    std::fs::create_dir_all(&root)?;
    Ok(root)
}

fn build_memory_runtime() -> Result<Arc<MemoryRuntime>> {
    Ok(Arc::new(MemoryRuntime::open_sqlite_in_memory()?))
}

fn parse_hex_hash_32(raw: &str) -> Option<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn read_incident_pending_gate_hash(
    state: &IAVLTree<HashCommitmentScheme>,
    session_id: [u8; 32],
) -> Option<[u8; 32]> {
    let key = [INCIDENT_PREFIX, session_id.as_slice()].concat();
    let bytes = state.get(&key).ok().flatten()?;
    let incident: IncidentState = codec::from_bytes_canonical(&bytes).ok()?;
    if !incident.active {
        return None;
    }
    incident
        .pending_gate
        .as_ref()
        .and_then(|gate| parse_hex_hash_32(&gate.request_hash))
}

fn build_approval_token_for_resume(
    request_hash: [u8; 32],
    now_ms: u64,
    pending_visual_hash: Option<[u8; 32]>,
) -> ApprovalToken {
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&request_hash);
    ApprovalToken {
        schema_version: 2,
        request_hash,
        audience: [0u8; 32],
        revocation_epoch: 0,
        nonce,
        counter: 1,
        scope: ApprovalScope {
            expires_at: now_ms.saturating_add(120_000),
            max_usages: Some(1),
        },
        visual_hash: pending_visual_hash,
        pii_action: None,
        scoped_exception: None,
        approver_sig: Vec::new(),
        approver_suite: SignatureSuite::ED25519,
    }
}

fn fixture_html() -> &'static str {
    r#"<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Browser Runtime Smoke</title>
  </head>
  <body data-status="pending">
    <main>
      <h1>Browser Runtime Smoke</h1>
      <p id="status">pending</p>
      <button id="mark-complete" type="button">Mark complete</button>
    </main>
    <script>
      const button = document.getElementById("mark-complete");
      const status = document.getElementById("status");
      button.addEventListener("click", () => {
        document.body.setAttribute("data-status", "done");
        status.textContent = "done";
      });
    </script>
  </body>
</html>
"#
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live external inference required for browser runtime smoke"]
async fn browser_live_http_runtime_smoke() -> Result<()> {
    build_test_artifacts();
    live_inference_support::load_env_from_workspace_dotenv_if_present();

    let artifact_root = artifact_root()?;
    let fixture_dir = tempdir()?;
    let fixture_path = fixture_dir.path().join("browser_live_runtime_smoke.html");
    std::fs::write(&fixture_path, fixture_html())?;
    let fixture_url = format!("file://{}", fixture_path.display());

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY is required for browser runtime smoke"))?;
    let api_url = std::env::var("OPENAI_API_URL")
        .unwrap_or_else(|_| live_inference_support::OPENAI_CHAT_COMPLETIONS_URL.to_string());
    let model_candidates = live_inference_support::configured_model_candidates(
        "IOI_BROWSER_LIVE_MODELS",
        "OPENAI_MODEL",
    );
    let model = live_inference_support::select_http_inference_model(
        &api_url,
        &openai_api_key,
        &model_candidates,
        "IOI_BROWSER_LIVE_MODEL_SELECTED",
    )
    .await?;

    let http_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url.clone(),
        openai_api_key,
        model.clone(),
    ));
    let counting_runtime = Arc::new(live_inference_support::CountingInferenceRuntime::new(
        http_runtime.clone(),
    ));
    let runtime: Arc<dyn InferenceRuntime> = counting_runtime.clone();

    let browser = Arc::new(BrowserDriver::new());
    browser.set_lease(true);
    browser.navigate(&fixture_url).await?;
    let memory_runtime = build_memory_runtime()?;

    let (tx, mut rx) = broadcast::channel(512);
    let service = DesktopAgentService::new_hybrid(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        browser.clone(),
        runtime.clone(),
        runtime.clone(),
    )
    .with_memory_runtime(memory_runtime)
    .with_event_sender(tx)
    .with_os_driver(Arc::new(NoopOsDriver));

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = [0xB7; 32];

    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&StartAgentParams {
                session_id,
                goal: "The current browser page is already open. Click the button labeled 'Mark complete' so the status text becomes done. Do not ask questions.".to_string(),
                max_steps: 8,
                parent_session_id: None,
                initial_budget: 1_600,
                mode: AgentMode::Agent,
            })
            .map_err(anyhow::Error::msg)?,
            &mut ctx,
        )
        .await
        .map_err(anyhow::Error::msg)?;

    apply_allow_all_policy(&mut state, session_id)?;

    let step_deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let service_call_timeout = Duration::from_secs(70);
    let mut kernel_events = Vec::new();
    let mut auto_resume_count = 0usize;
    let mut paused_reason = None::<String>;
    let mut service_error = None::<String>;
    const MAX_AUTO_APPROVAL_RESUMES: usize = 4;
    while tokio::time::Instant::now() < step_deadline {
        drain_events(&mut rx, &mut kernel_events);
        let agent_state = read_agent_state(&state, session_id)?;
        match &agent_state.status {
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => break,
            AgentStatus::Paused(reason) => {
                let waiting_for_approval = reason.to_ascii_lowercase().contains("approval");
                if waiting_for_approval && auto_resume_count < MAX_AUTO_APPROVAL_RESUMES {
                    let request_hash = read_incident_pending_gate_hash(&state, session_id)
                        .or(agent_state.pending_tool_hash);
                    let Some(request_hash) = request_hash else {
                        paused_reason = Some(reason.clone());
                        service_error = Some(
                            "approval pause missing pending request hash for resume".to_string(),
                        );
                        break;
                    };
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let approval_token = build_approval_token_for_resume(
                        request_hash,
                        now_ms,
                        agent_state.pending_visual_hash,
                    );
                    match tokio::time::timeout(
                        service_call_timeout,
                        service.handle_service_call(
                            &mut state,
                            "resume@v1",
                            &codec::to_bytes_canonical(&ResumeAgentParams {
                                session_id,
                                approval_token: Some(approval_token),
                            })
                            .map_err(anyhow::Error::msg)?,
                            &mut ctx,
                        ),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {
                            auto_resume_count = auto_resume_count.saturating_add(1);
                            continue;
                        }
                        Ok(Err(err)) => {
                            paused_reason = Some(reason.clone());
                            service_error = Some(err.to_string());
                            break;
                        }
                        Err(_) => {
                            paused_reason = Some(reason.clone());
                            service_error = Some(
                                "browser runtime smoke timed out while resuming approval"
                                    .to_string(),
                            );
                            break;
                        }
                    }
                }
                paused_reason = Some(reason.clone());
                break;
            }
            AgentStatus::Idle | AgentStatus::Running | AgentStatus::Terminated => {}
        }

        match tokio::time::timeout(
            service_call_timeout,
            service.handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(anyhow::Error::msg)?,
                &mut ctx,
            ),
        )
        .await
        {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => {
                service_error = Some(err.to_string());
                break;
            }
            Err(_) => {
                service_error = Some("browser runtime smoke timed out while stepping".to_string());
                break;
            }
        }
    }
    drain_events(&mut rx, &mut kernel_events);

    let agent_state = read_agent_state(&state, session_id)?;
    let final_status = format!("{:?}", agent_state.status);
    let final_reply = match &agent_state.status {
        AgentStatus::Completed(Some(text)) => Some(text.clone()),
        _ => None,
    };
    let dom = browser.extract_dom().await?;
    let active_url = browser.active_url().await?;
    let screenshot = browser.capture_tab_screenshot(false).await?;
    std::fs::write(artifact_root.join("browser.jpg"), &screenshot)?;
    std::fs::write(
        artifact_root.join("kernel-events.txt"),
        kernel_events.join("\n"),
    )?;
    std::fs::write(
        artifact_root.join("inference-calls.json"),
        serde_json::to_vec_pretty(&counting_runtime.call_records())?,
    )?;

    let dom_contains_done =
        dom.contains("data-status=\"done\"") || dom.contains(">done<") || dom.contains("done</p>");
    let inference_calls = counting_runtime.call_count();
    let summary = json!({
        "artifacts": {
            "browser_screenshot": artifact_root.join("browser.jpg").display().to_string(),
            "kernel_events": artifact_root.join("kernel-events.txt").display().to_string(),
            "inference_calls": artifact_root.join("inference-calls.json").display().to_string(),
        },
        "fixture": {
            "path": fixture_path.display().to_string(),
            "url": fixture_url,
        },
        "inference": {
            "api_url": api_url,
            "model": model,
            "runtime_kind": "HttpInferenceRuntime",
            "call_count": inference_calls,
        },
        "result": {
            "active_url": active_url,
            "agent_status": final_status,
            "auto_resume_count": auto_resume_count,
            "dom_contains_done": dom_contains_done,
            "final_reply": final_reply,
            "paused_reason": paused_reason,
            "service_error": service_error,
        },
    });
    std::fs::write(
        artifact_root.join("summary.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;

    anyhow::ensure!(
        service_error.is_none(),
        "browser runtime smoke service call failed; summary={}",
        serde_json::to_string_pretty(&summary)?
    );
    anyhow::ensure!(
        inference_calls > 0,
        "no live inference calls were observed; summary={}",
        serde_json::to_string_pretty(&summary)?
    );
    anyhow::ensure!(
        dom_contains_done,
        "typed postcondition failed for browser runtime smoke; summary={}",
        serde_json::to_string_pretty(&summary)?
    );

    Ok(())
}
