use super::approvals::is_runtime_secret_install_retry_approved;
use super::execution_request_nonce;
use super::focus::is_focus_sensitive_tool;
use super::query_active_window_with_timeout;
use super::target_requires_window_binding;
use super::{normalize_web_research_tool_call, reconcile_pending_web_research_tool_call};
use crate::agentic::runtime::runtime_secret;
use crate::agentic::runtime::service::RuntimeAgentService;
use crate::agentic::runtime::types::{
    AgentMode, AgentState, AgentStatus, CommandExecution, ExecutionTier, PendingSearchCompletion,
    PendingSearchReadSummary, WorkerAssignment,
};
use async_trait::async_trait;
use ioi_api::state::StateScanIter;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{
    ImageEditRequest, ImageGenerationRequest, ImageGenerationResult, InferenceRuntime,
    SpeechSynthesisRequest, SpeechSynthesisResult, TextGenerationRequest, TextGenerationResult,
    TranscriptionRequest, TranscriptionResult, VideoGenerationRequest, VideoGenerationResult,
    VisionReadRequest, VisionReadResult,
};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::agentic::{
    AgentTool, ComputerAction, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
    WebRetrievalContract,
};
use ioi_types::app::{
    AccountId, ActionRequest, ActionTarget, ChainId, ContextSlice, InferenceOperationKind,
    KernelEvent, ModelLifecycleOperationKind, NetMode, RegistrySubjectKind, RuntimeTarget,
    WorkloadActivityKind, WorkloadReceipt,
};
use ioi_types::error::StateError;
use ioi_types::error::VmError;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration, Instant};

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
        active_skill_hash: None,
        tool_execution_log: BTreeMap::new(),
        visual_som_map: None,
        visual_semantic_map: None,
        swarm_context: None,
        target: None,
        resolved_intent: None,

        awaiting_intent_clarification: false,

        working_directory: ".".to_string(),
        active_lens: None,
        pending_search_completion: None,
        planner_state: None,
        command_history: Default::default(),
    }
}

#[test]
fn right_click_variants_require_focus_recovery() {
    assert!(is_focus_sensitive_tool(&AgentTool::Computer(
        ComputerAction::RightClick {
            coordinate: Some([10, 20]),
        },
    )));
    assert!(is_focus_sensitive_tool(&AgentTool::Computer(
        ComputerAction::RightClickId { id: 12 },
    )));
    assert!(is_focus_sensitive_tool(&AgentTool::Computer(
        ComputerAction::RightClickElement {
            id: "file_row".to_string(),
        },
    )));
}

#[test]
fn browser_click_tools_do_not_require_native_focus_recovery() {
    assert!(!is_focus_sensitive_tool(&AgentTool::BrowserClick {
        selector: "#submit".to_string(),
    }));
    assert!(!is_focus_sensitive_tool(&AgentTool::BrowserClickElement {
        id: Some("btn_submit".to_string()),
        ids: Vec::new(),
        delay_ms_between_ids: None,
        continue_with: None,
    }));
    assert!(!is_focus_sensitive_tool(
        &AgentTool::BrowserSyntheticClick {
            id: None,
            x: Some(20.0),
            y: Some(30.0),
            continue_with: None,
        }
    ));
}

#[test]
fn desktop_screenshot_does_not_require_window_binding() {
    assert!(
        !target_requires_window_binding(&ActionTarget::GuiScreenshot),
        "full-display screenshot capture should not depend on a foreground-window binding"
    );
    assert!(
        target_requires_window_binding(&ActionTarget::GuiClick),
        "interactive GUI clicks should remain window-bound"
    );
}

struct SlowWindowOsDriver;

#[async_trait]
impl OsDriver for SlowWindowOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(None)
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        sleep(Duration::from_secs(5)).await;
        Ok(None)
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

struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

#[derive(Default)]
struct RecordingInferenceRuntime {
    generated_inputs: Mutex<Vec<Vec<u8>>>,
    load_calls: Mutex<Vec<([u8; 32], String)>>,
    transcription_calls: Mutex<Vec<String>>,
}

#[async_trait]
impl InferenceRuntime for RecordingInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: ioi_types::app::InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        Ok(Vec::new())
    }

    async fn generate_text(
        &self,
        request: TextGenerationRequest,
    ) -> Result<TextGenerationResult, VmError> {
        self.generated_inputs
            .lock()
            .expect("generated_inputs mutex poisoned")
            .push(request.input_context.clone());
        Ok(TextGenerationResult {
            output: b"kernel-native output".to_vec(),
            model_id: request
                .model_id
                .or_else(|| Some("recorded-model".to_string())),
            streamed: request.stream,
        })
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        Ok(vec![text.len() as f32, 1.0])
    }

    async fn transcribe_audio(
        &self,
        request: TranscriptionRequest,
    ) -> Result<TranscriptionResult, VmError> {
        self.transcription_calls
            .lock()
            .expect("transcription_calls mutex poisoned")
            .push(request.mime_type.clone());
        Ok(TranscriptionResult {
            text: "kernel transcript".to_string(),
            language: request.language.or_else(|| Some("en".to_string())),
            model_id: request
                .model_id
                .or_else(|| Some("recorded-transcriber".to_string())),
        })
    }

    async fn synthesize_speech(
        &self,
        request: SpeechSynthesisRequest,
    ) -> Result<SpeechSynthesisResult, VmError> {
        Ok(SpeechSynthesisResult {
            audio_bytes: request.text.into_bytes(),
            mime_type: request.mime_type.unwrap_or_else(|| "audio/wav".to_string()),
            model_id: request
                .model_id
                .or_else(|| Some("recorded-tts".to_string())),
        })
    }

    async fn vision_read(&self, request: VisionReadRequest) -> Result<VisionReadResult, VmError> {
        Ok(VisionReadResult {
            output_text: format!(
                "vision:{}:{}",
                request.mime_type,
                request.prompt.unwrap_or_else(|| "no-prompt".to_string())
            ),
            model_id: request
                .model_id
                .or_else(|| Some("recorded-vision".to_string())),
        })
    }

    async fn generate_image(
        &self,
        request: ImageGenerationRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        Ok(ImageGenerationResult {
            image_bytes: request.prompt.into_bytes(),
            mime_type: request.mime_type.unwrap_or_else(|| "image/png".to_string()),
            model_id: request
                .model_id
                .or_else(|| Some("recorded-image".to_string())),
        })
    }

    async fn edit_image(
        &self,
        request: ImageEditRequest,
    ) -> Result<ImageGenerationResult, VmError> {
        Ok(ImageGenerationResult {
            image_bytes: request
                .prompt
                .unwrap_or_else(|| "recorded-image-edit".to_string())
                .into_bytes(),
            mime_type: request.source_mime_type,
            model_id: request
                .model_id
                .or_else(|| Some("recorded-image-edit".to_string())),
        })
    }

    async fn generate_video(
        &self,
        request: VideoGenerationRequest,
    ) -> Result<VideoGenerationResult, VmError> {
        Ok(VideoGenerationResult {
            video_bytes: request.prompt.into_bytes(),
            mime_type: request.mime_type.unwrap_or_else(|| "video/mp4".to_string()),
            model_id: request
                .model_id
                .or_else(|| Some("recorded-video".to_string())),
        })
    }

    async fn load_model(&self, model_hash: [u8; 32], path: &Path) -> Result<(), VmError> {
        self.load_calls
            .lock()
            .expect("load_calls mutex poisoned")
            .push((model_hash, path.display().to_string()));
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

fn build_test_service(
    inference: Arc<dyn InferenceRuntime>,
    event_sender: Option<tokio::sync::broadcast::Sender<KernelEvent>>,
) -> RuntimeAgentService {
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let mut service = RuntimeAgentService::new(gui, terminal, browser, inference);
    if let Some(sender) = event_sender {
        service = service.with_event_sender(sender);
    }
    service
}

#[tokio::test]
async fn active_window_query_timeout_returns_none_without_blocking() {
    let os_driver: Arc<dyn OsDriver> = Arc::new(SlowWindowOsDriver);
    let started = Instant::now();
    let result = query_active_window_with_timeout(&os_driver, [0u8; 32], "test").await;
    let elapsed = started.elapsed();

    assert!(result.is_none());
    assert!(
        elapsed < Duration::from_secs(2),
        "active window timeout guard took too long: {:?}",
        elapsed
    );
}

#[test]
fn runtime_secret_retry_is_approved_only_for_matching_pending_install() {
    let session_id = [9u8; 32];
    let session_hex = hex::encode(session_id);
    runtime_secret::set_secret(&session_hex, "sudo_password", "pw".to_string(), true, 60)
        .expect("set runtime sudo secret");

    let mut state = test_agent_state();
    let hash = [7u8; 32];
    state.pending_tool_hash = Some(hash);

    let install_tool = AgentTool::SysInstallPackage {
        package: "gnome-calculator".to_string(),
        manager: Some("apt-get".to_string()),
    };
    assert!(is_runtime_secret_install_retry_approved(
        &install_tool,
        hash,
        session_id,
        &state
    ));

    assert!(!is_runtime_secret_install_retry_approved(
        &install_tool,
        [8u8; 32],
        session_id,
        &state
    ));

    let non_install = AgentTool::SysExec {
        command: "echo".to_string(),
        args: vec!["ok".to_string()],
        stdin: None,
        detach: false,
    };
    assert!(!is_runtime_secret_install_retry_approved(
        &non_install,
        hash,
        session_id,
        &state
    ));
}

#[test]
fn pending_request_nonce_is_reused_for_canonical_resume() {
    let mut state = test_agent_state();
    state.pending_request_nonce = Some(7);

    assert_eq!(execution_request_nonce(&state, 11), 7);

    state.pending_request_nonce = None;
    assert_eq!(execution_request_nonce(&state, 11), 11);
}

fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "test".to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.95,
        top_k: vec![],
        required_capabilities: vec![],
        required_receipts: vec![],
        required_postconditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        matrix_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        matrix_source_hash: [0u8; 32],
        receipt_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

#[test]
fn rewrites_search_navigation_to_web_search_for_web_research_scope() {
    let mut tool = AgentTool::BrowserNavigate {
        url: "https://duckduckgo.com/?q=latest+news".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);

    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "latest news");
            assert_eq!(query_contract.as_deref(), Some("fallback query"));
            assert!(retrieval_contract.is_none());
            assert_eq!(
                    limit,
                    Some(crate::agentic::runtime::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
                );
            let expected = crate::agentic::web::build_default_search_url("latest news");
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn rewrites_direct_navigation_to_web_read_for_web_research_scope() {
    let mut tool = AgentTool::BrowserNavigate {
        url: "https://example.com/news".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback query");

    match tool {
        AgentTool::WebRead {
            url,
            max_chars,
            allow_browser_fallback,
        } => {
            assert_eq!(url, "https://example.com/news");
            assert_eq!(max_chars, None);
            assert_eq!(allow_browser_fallback, None);
        }
        other => panic!("expected WebRead, got {:?}", other),
    }
}

#[test]
fn rewrites_browser_snapshot_to_web_search_for_web_research_scope() {
    let mut tool = AgentTool::BrowserSnapshot {};
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "italian menus");
            assert_eq!(
                query_contract.as_deref(),
                Some(
                    "Find the three best-reviewed Italian restaurants near me and compare their menus."
                )
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                limit,
                Some(crate::agentic::runtime::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
            );
            let expected = crate::agentic::web::build_default_search_url("italian menus");
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn does_not_rewrite_non_search_navigation_or_non_web_scope() {
    let mut scoped_tool = AgentTool::BrowserNavigate {
        url: "https://duckduckgo.com/?q=latest+news".to_string(),
    };
    let non_web_intent = resolved(IntentScopeProfile::Conversation);
    normalize_web_research_tool_call(&mut scoped_tool, Some(&non_web_intent), "fallback");
    assert!(matches!(scoped_tool, AgentTool::BrowserNavigate { .. }));

    let mut non_http_tool = AgentTool::BrowserNavigate {
        url: "about:blank".to_string(),
    };
    let web_intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut non_http_tool, Some(&web_intent), "fallback");
    assert!(matches!(non_http_tool, AgentTool::BrowserNavigate { .. }));
}

#[test]
fn does_not_rewrite_browser_actions_when_goal_explicitly_forbids_web_retrieval() {
    let mut tool = AgentTool::BrowserType {
        text: "dispatch.agent".to_string(),
        selector: Some("#username".to_string()),
    };
    let intent = resolved(IntentScopeProfile::UiInteraction);

    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "Navigate to the assigned MiniWoB page and complete the on-page task using browser tools only. Do not use web retrieval tools. Search the queue for fiber, switch the sort to Recently Updated, and verify the saved dispatch update was not persisted.",
    );

    match tool {
        AgentTool::BrowserType { text, selector } => {
            assert_eq!(text, "dispatch.agent");
            assert_eq!(selector.as_deref(), Some("#username"));
        }
        other => panic!("expected BrowserType, got {:?}", other),
    }
}

#[test]
fn redirects_exhausted_pending_web_read_to_next_grounded_candidate() {
    let exhausted_url = "https://example.com/archive";
    let replacement_url = "https://example.com/latest";
    let mut tool = AgentTool::WebRead {
        url: exhausted_url.to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    };
    let pending = PendingSearchCompletion {
        query: "Read the latest incident report updates.".to_string(),
        query_contract: "Read the latest incident report updates.".to_string(),
        retrieval_contract: None,
        url: "https://www.google.com/search?q=incident+report+updates".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![exhausted_url.to_string(), replacement_url.to_string()],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: exhausted_url.to_string(),
                title: Some("Older update".to_string()),
                excerpt: "Outdated incident report.".to_string(),
            },
            PendingSearchReadSummary {
                url: replacement_url.to_string(),
                title: Some("Current update".to_string()),
                excerpt: "Current incident report.".to_string(),
            },
        ],
        attempted_urls: vec![exhausted_url.to_string()],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    let replacement = reconcile_pending_web_research_tool_call(&mut tool, Some(&pending));

    assert_eq!(
        replacement,
        Some((exhausted_url.to_string(), replacement_url.to_string()))
    );
    match tool {
        AgentTool::WebRead { url, .. } => assert_eq!(url, replacement_url),
        other => panic!("expected WebRead, got {:?}", other),
    }
}

#[test]
fn does_not_redirect_exhausted_pending_web_read_when_query_contract_disallows_fallback() {
    let exhausted_url = "https://csrc.nist.gov/projects/post-quantum-cryptography";
    let replacement_url = "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption";
    let mut tool = AgentTool::WebRead {
        url: exhausted_url.to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    };
    let pending = PendingSearchCompletion {
        query:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(ioi_types::app::agentic::WebRetrievalContract {
            contract_version: "web_retrieval_contract.v1".to_string(),
            browser_fallback_allowed: false,
            ..Default::default()
        }),
        url: "https://www.google.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![exhausted_url.to_string(), replacement_url.to_string()],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: exhausted_url.to_string(),
                title: Some("Post-Quantum Cryptography".to_string()),
                excerpt: "NIST project page for post-quantum cryptography.".to_string(),
            },
            PendingSearchReadSummary {
                url: replacement_url.to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt:
                    "NIST selected HQC in March 2025 as the fifth post-quantum encryption algorithm."
                        .to_string(),
            },
        ],
        attempted_urls: vec![exhausted_url.to_string()],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    let replacement = reconcile_pending_web_research_tool_call(&mut tool, Some(&pending));

    assert_eq!(replacement, None);
    match tool {
        AgentTool::WebRead { url, .. } => assert_eq!(url, exhausted_url),
        other => panic!("expected WebRead, got {:?}", other),
    }
}

#[test]
fn leaves_fresh_pending_web_read_unchanged() {
    let fresh_url = "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
    let mut tool = AgentTool::WebRead {
        url: fresh_url.to_string(),
        max_chars: None,
        allow_browser_fallback: None,
    };
    let pending = PendingSearchCompletion {
        query:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: None,
        url: "https://www.google.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![fresh_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: fresh_url.to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            excerpt: "NIST finalized ML-KEM, ML-DSA and SLH-DSA in August 2024.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    assert_eq!(
        reconcile_pending_web_research_tool_call(&mut tool, Some(&pending)),
        None
    );
    match tool {
        AgentTool::WebRead { url, .. } => assert_eq!(url, fresh_url),
        other => panic!("expected WebRead, got {:?}", other),
    }
}

#[test]
fn normalizes_direct_web_search_limit_for_web_research_scope() {
    let mut tool = AgentTool::WebSearch {
        query: "top US breaking news last 6 hours".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: Some(3),
        url: None,
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "top US breaking news last 6 hours");
            assert_eq!(query_contract.as_deref(), Some("fallback"));
            assert!(retrieval_contract.is_none());
            assert_eq!(
                    limit,
                    Some(crate::agentic::runtime::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
                );
            let expected =
                crate::agentic::web::build_default_search_url("top US breaking news last 6 hours");
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn normalizes_web_search_query_contract_from_resolved_locality_query() {
    let mut tool = AgentTool::WebSearch {
        query: "best-reviewed Italian restaurants in Anderson, SC".to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: Some(3),
        url: None,
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "best-reviewed Italian restaurants in Anderson, SC");
            assert_eq!(
                query_contract.as_deref(),
                Some(
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                )
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                limit,
                Some(crate::agentic::runtime::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
            );
            let expected = crate::agentic::web::build_default_search_url(
                "best-reviewed Italian restaurants in Anderson, SC",
            );
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn preserves_precomputed_web_search_retrieval_contract_when_query_contract_is_present() {
    let mut tool = AgentTool::WebSearch {
        query: "best-reviewed Italian restaurants in Anderson, SC".to_string(),
        query_contract: Some(
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                .to_string(),
        ),
        retrieval_contract: Some(WebRetrievalContract {
            contract_version: "test.v1".to_string(),
            entity_cardinality_min: 3,
            comparison_required: true,
            currentness_required: true,
            runtime_locality_required: true,
            source_independence_min: 3,
            citation_count_min: 1,
            structured_record_preferred: false,
            ordered_collection_preferred: false,
            link_collection_preferred: true,
            canonical_link_out_preferred: true,
            geo_scoped_detail_required: true,
            discovery_surface_required: true,
            entity_diversity_required: true,
            scalar_measure_required: false,
            browser_fallback_allowed: true,
        }),
        limit: Some(3),
        url: None,
    };
    let intent = resolved(IntentScopeProfile::WebResearch);

    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );

    match tool {
        AgentTool::WebSearch {
            retrieval_contract, ..
        } => {
            assert!(retrieval_contract.is_some());
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn rewrites_memory_search_to_web_search_for_web_research_scope() {
    let mut tool = AgentTool::MemorySearch {
        query: "active cloud incidents us impact".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(&mut tool, Some(&intent), "fallback");

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "active cloud incidents us impact");
            assert_eq!(query_contract.as_deref(), Some("fallback"));
            assert!(retrieval_contract.is_none());
            assert_eq!(
                    limit,
                    Some(crate::agentic::runtime::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
                );
            let expected =
                crate::agentic::web::build_default_search_url("active cloud incidents us impact");
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn rewrites_empty_memory_search_with_fallback_for_web_research_scope() {
    let mut tool = AgentTool::MemorySearch {
        query: "   ".to_string(),
    };
    let intent = resolved(IntentScopeProfile::WebResearch);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&intent),
        "as of now top active us cloud incidents",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            url,
        } => {
            assert_eq!(query, "as of now top active us cloud incidents");
            assert_eq!(
                query_contract.as_deref(),
                Some("as of now top active us cloud incidents")
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                    limit,
                    Some(crate::agentic::runtime::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
                );
            let expected = crate::agentic::web::build_default_search_url(
                "as of now top active us cloud incidents",
            );
            assert_eq!(url.as_deref(), Some(expected.as_str()));
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn rewrites_memory_search_when_goal_is_live_external_even_if_scope_is_not_web() {
    let mut tool = AgentTool::MemorySearch {
        query: "active cloud incidents us impact".to_string(),
    };
    let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&workspace_intent),
        "As of now (UTC), top active cloud incidents with citations",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            ..
        } => {
            assert_eq!(query, "active cloud incidents us impact");
            assert_eq!(
                query_contract.as_deref(),
                Some("As of now (UTC), top active cloud incidents with citations")
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                limit,
                Some(crate::agentic::runtime::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
            );
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn normalizes_live_external_restaurant_search_even_if_scope_is_not_web() {
    let mut tool = AgentTool::WebSearch {
        query: "italian restaurants menus in Anderson, SC \"italian restaurants menus\" \"Anderson, SC\""
            .to_string(),
        query_contract: None,
        retrieval_contract: None,
        limit: Some(3),
        url: None,
    };
    let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);

    normalize_web_research_tool_call(
        &mut tool,
        Some(&workspace_intent),
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
    );

    match tool {
        AgentTool::WebSearch {
            query,
            query_contract,
            retrieval_contract,
            limit,
            ..
        } => {
            let normalized = query.to_ascii_lowercase();
            assert!(
                normalized.contains("italian restaurants in anderson")
                    || normalized.contains("restaurants in anderson"),
                "query={query}"
            );
            assert!(!normalized.contains("compare"), "query={query}");
            assert!(
                !normalized.contains("\"italian restaurants menus\""),
                "query={query}"
            );
            assert_eq!(
                query_contract.as_deref(),
                Some(
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                )
            );
            assert!(retrieval_contract.is_none());
            assert_eq!(
                limit,
                Some(crate::agentic::runtime::service::step::queue::web_pipeline::WEB_PIPELINE_SEARCH_LIMIT)
            );
        }
        other => panic!("expected WebSearch, got {:?}", other),
    }
}

#[test]
fn does_not_rewrite_memory_search_for_workspace_local_goal() {
    let mut tool = AgentTool::MemorySearch {
        query: "intent resolver".to_string(),
    };
    let workspace_intent = resolved(IntentScopeProfile::WorkspaceOps);
    normalize_web_research_tool_call(
        &mut tool,
        Some(&workspace_intent),
        "Search the repository for intent resolver code and patch tests",
    );

    assert!(matches!(tool, AgentTool::MemorySearch { .. }));
}

#[test]
fn patch_build_verify_rewrites_initial_mismatched_exec_to_targeted_check() {
    let mut state = test_agent_state();
    let assignment = WorkerAssignment {
        step_key: "implement".to_string(),
        budget: 32,
        goal: "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string(),
        success_criteria: "Run focused verification first.".to_string(),
        max_retries: 2,
        retries_used: 0,
        assigned_session_id: None,
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coding_worker".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec!["sys__exec_session".to_string()],
        completion_contract: Default::default(),
    };
    let mut tool = AgentTool::SysExecSession {
        command: "python".to_string(),
        args: vec![
            "-c".to_string(),
            "import sys; sys.path.append('/tmp/example'); import path_utils; path_utils.test_path_utils()".to_string(),
        ],
        stdin: None,
    };

    let changed = super::normalize_patch_build_verify_targeted_exec_tool(
        &mut tool,
        &state,
        Some(&assignment),
    );

    assert!(changed);
    match tool {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "bash");
            assert_eq!(
                args,
                vec![
                    "-lc".to_string(),
                    "python3 -m unittest tests.test_path_utils -v".to_string()
                ]
            );
        }
        other => panic!("expected SysExecSession, got {:?}", other),
    }
}

#[test]
fn patch_build_verify_does_not_rewrite_after_targeted_command_history_exists() {
    let mut state = test_agent_state();
    state.command_history.push_back(CommandExecution {
        command: "bash -lc python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 1,
        stdout: String::new(),
        stderr: String::new(),
        timestamp_ms: 1,
        step_index: 2,
    });
    let assignment = WorkerAssignment {
        step_key: "implement".to_string(),
        budget: 32,
        goal: "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v".to_string(),
        success_criteria: "Run focused verification first.".to_string(),
        max_retries: 2,
        retries_used: 0,
        assigned_session_id: None,
        status: "running".to_string(),
        playbook_id: Some("evidence_audited_patch".to_string()),
        template_id: Some("coding_worker".to_string()),
        workflow_id: Some("patch_build_verify".to_string()),
        role: Some("Coding Worker".to_string()),
        allowed_tools: vec!["sys__exec_session".to_string()],
        completion_contract: Default::default(),
    };
    let mut tool = AgentTool::SysExecSession {
        command: "python".to_string(),
        args: vec![
            "-c".to_string(),
            "import sys; sys.path.append('/tmp/example'); import path_utils; path_utils.test_path_utils()".to_string(),
        ],
        stdin: None,
    };

    let changed = super::normalize_patch_build_verify_targeted_exec_tool(
        &mut tool,
        &state,
        Some(&assignment),
    );

    assert!(!changed);
    match tool {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "python");
            assert_eq!(
                args,
                vec![
                    "-c".to_string(),
                    "import sys; sys.path.append('/tmp/example'); import path_utils; path_utils.test_path_utils()".to_string()
                ]
            );
        }
        other => panic!("expected SysExecSession, got {:?}", other),
    }
}

#[derive(Default)]
struct MockState {
    data: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl ioi_api::state::StateAccess for MockState {
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

#[test]
fn firewall_attestation_signatures_are_real_and_verifiable() {
    let mut state = MockState::default();
    let attestation = b"firewall.attestation.payload";
    let ctx = Some((ChainId(7), AccountId([9u8; 32])));

    let sig = super::sign_firewall_attestation(&mut state, ctx, attestation)
        .expect("signature envelope should be generated");
    super::verify_firewall_attestation_signature(attestation, &sig)
        .expect("signature envelope should verify");
}

#[test]
fn firewall_attestation_signature_is_deterministic_for_same_signer_and_payload() {
    let mut state = MockState::default();
    let attestation = b"deterministic.payload";
    let ctx = Some((ChainId(1), AccountId([3u8; 32])));

    let first =
        super::sign_firewall_attestation(&mut state, ctx, attestation).expect("first signature");
    let second =
        super::sign_firewall_attestation(&mut state, ctx, attestation).expect("second signature");

    assert_eq!(first, second);
}

#[test]
fn runtime_target_maps_dynamic_tools_to_adapter() {
    let tool = AgentTool::Dynamic(serde_json::json!({
        "name": "filesystem__read_file",
        "arguments": { "path": "README.md" }
    }));
    assert_eq!(
        super::runtime_target_for_tool(&tool),
        RuntimeTarget::Adapter
    );
}

#[test]
fn runtime_target_maps_model_dynamic_tools_to_inference() {
    let tool = AgentTool::Dynamic(serde_json::json!({
        "name": "model__responses",
        "arguments": { "prompt": "hello" }
    }));
    assert_eq!(
        super::runtime_target_for_tool(&tool),
        RuntimeTarget::Inference
    );
}

#[test]
fn runtime_target_maps_media_tools_to_media() {
    let typed_tool = AgentTool::MediaExtractTranscript {
        url: "https://example.com/video".to_string(),
        language: Some("en".to_string()),
        max_chars: Some(512),
    };
    assert_eq!(
        super::runtime_target_for_tool(&typed_tool),
        RuntimeTarget::Media
    );

    let dynamic_tool = AgentTool::Dynamic(serde_json::json!({
        "name": "media__extract_multimodal_evidence",
        "arguments": { "url": "https://example.com/video" }
    }));
    assert_eq!(
        super::runtime_target_for_tool(&dynamic_tool),
        RuntimeTarget::Media
    );
}

#[test]
fn runtime_target_maps_model_registry_dynamic_tools_to_model_registry() {
    let tool = AgentTool::Dynamic(serde_json::json!({
        "name": "model_registry__install",
        "arguments": { "source_uri": "https://models.example.com/demo.gguf" }
    }));
    assert_eq!(
        super::runtime_target_for_tool(&tool),
        RuntimeTarget::ModelRegistry
    );
}

#[test]
fn runtime_target_maps_google_connector_dynamic_tools_to_adapter() {
    let tool = AgentTool::Dynamic(serde_json::json!({
        "name": "connector__google__gmail_read_emails",
        "arguments": { "query": "is:unread" }
    }));
    assert_eq!(
        super::runtime_target_for_tool(&tool),
        RuntimeTarget::Adapter
    );
}

#[test]
fn build_workload_spec_binds_domain_and_allowlisted_net_mode_for_net_fetch() {
    let tool = AgentTool::NetFetch {
        url: "https://api.example.com/v1/status".to_string(),
        max_chars: Some(256),
    };
    let (spec, observed_domain) =
        super::build_workload_spec(&tool, &ActionTarget::NetFetch, [5u8; 32], None, None, 2_000);

    assert_eq!(spec.runtime_target, RuntimeTarget::Network);
    assert_eq!(spec.net_mode, NetMode::AllowListed);
    assert_eq!(observed_domain.as_deref(), Some("api.example.com"));

    let lease = spec
        .capability_lease
        .as_ref()
        .expect("net fetch should mint capability lease");
    assert!(lease.allows_capability("net::fetch"));
    assert!(lease.allows_domain("status.api.example.com"));
}

#[test]
fn build_workload_spec_binds_media_runtime_and_allowlisted_net_mode_for_remote_media_tool() {
    let tool = AgentTool::MediaExtractTranscript {
        url: "https://media.example.com/watch/demo".to_string(),
        language: Some("en".to_string()),
        max_chars: Some(256),
    };
    let (spec, observed_domain) = super::build_workload_spec(
        &tool,
        &ActionTarget::MediaExtractTranscript,
        [6u8; 32],
        None,
        None,
        2_500,
    );

    assert_eq!(spec.runtime_target, RuntimeTarget::Media);
    assert_eq!(spec.net_mode, NetMode::AllowListed);
    assert_eq!(observed_domain.as_deref(), Some("media.example.com"));

    let lease = spec
        .capability_lease
        .as_ref()
        .expect("media tool should mint capability lease");
    assert!(lease.allows_capability("media::extract_transcript"));
    assert!(lease.allows_domain("cdn.media.example.com"));
}

#[test]
fn build_workload_spec_observes_model_registry_source_domains() {
    let tool = AgentTool::Dynamic(serde_json::json!({
        "name": "model_registry__install",
        "arguments": { "source_uri": "https://models.example.com/demo.gguf" }
    }));
    let (spec, observed_domain) = super::build_workload_spec(
        &tool,
        &ActionTarget::Custom("model_registry__install".to_string()),
        [4u8; 32],
        None,
        None,
        3_000,
    );

    assert_eq!(spec.runtime_target, RuntimeTarget::ModelRegistry);
    assert_eq!(spec.net_mode, NetMode::AllowListed);
    assert_eq!(observed_domain.as_deref(), Some("models.example.com"));

    let lease = spec
        .capability_lease
        .as_ref()
        .expect("registry install should mint capability lease");
    assert!(lease.allows_domain("cdn.models.example.com"));
}

#[tokio::test(flavor = "current_thread")]
async fn native_dynamic_model_responses_execute_and_emit_inference_receipt() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime.clone(), Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "model__responses",
        "arguments": {
            "prompt": "hello from kernel",
            "model_id": "codex-oss-local",
            "stream": true
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [7u8; 32],
        3,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("tool should be admitted natively");

    assert!(result.0);
    let history = result.1.expect("successful tool should emit history");
    assert!(history.contains("kernel-native output"));

    let generated_inputs = runtime
        .generated_inputs
        .lock()
        .expect("generated_inputs mutex poisoned");
    assert_eq!(generated_inputs.len(), 1);
    assert_eq!(
        String::from_utf8(generated_inputs[0].clone()).expect("prompt should be utf8"),
        "hello from kernel"
    );
    drop(generated_inputs);

    let mut activity_phases = Vec::new();
    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        match event {
            KernelEvent::WorkloadActivity(activity) => {
                if let WorkloadActivityKind::Lifecycle { phase, .. } = activity.kind {
                    activity_phases.push(phase);
                }
            }
            KernelEvent::WorkloadReceipt(receipt_event) => match receipt_event.receipt {
                WorkloadReceipt::Inference(receipt) => {
                    assert_eq!(receipt.tool_name, "model__responses");
                    assert_eq!(receipt.operation, InferenceOperationKind::TextGeneration);
                    assert_eq!(receipt.model_id, "codex-oss-local");
                    assert!(receipt.streaming);
                    assert!(receipt.success);
                    saw_receipt = true;
                }
                other => panic!("expected inference receipt, got {:?}", other),
            },
            _ => {}
        }
    }

    assert_eq!(
        activity_phases,
        vec!["started".to_string(), "completed".to_string()]
    );
    assert!(saw_receipt, "expected inference workload receipt");
}

#[tokio::test(flavor = "current_thread")]
async fn native_dynamic_model_registry_load_executes_and_emits_lifecycle_receipt() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime.clone(), Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "model_registry__load",
        "arguments": {
            "model_id": "demo-model",
            "path": "/tmp/demo.gguf"
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [8u8; 32],
        4,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("registry load should be admitted natively");

    assert!(result.0);
    let load_calls = runtime
        .load_calls
        .lock()
        .expect("load_calls mutex poisoned");
    assert_eq!(load_calls.len(), 1);
    assert_eq!(load_calls[0].1, "/tmp/demo.gguf");
    drop(load_calls);

    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::ModelLifecycle(receipt) => {
                    assert_eq!(receipt.tool_name, "model_registry__load");
                    assert_eq!(receipt.operation, ModelLifecycleOperationKind::Load);
                    assert_eq!(receipt.subject_kind, RegistrySubjectKind::Model);
                    assert_eq!(receipt.subject_id, "demo-model");
                    assert!(receipt.success);
                    saw_receipt = true;
                }
                other => panic!("expected model lifecycle receipt, got {:?}", other),
            }
        }
    }

    assert!(saw_receipt, "expected lifecycle workload receipt");
}

#[tokio::test(flavor = "current_thread")]
async fn model_registry_install_is_accepted_as_kernel_control_plane_job() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime, Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "model_registry__install",
        "arguments": {
            "model_id": "demo-model",
            "source_uri": "https://models.example.com/demo.gguf"
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [9u8; 32],
        5,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("reserved registry family should be admitted natively");

    assert!(result.0);
    let history = result
        .1
        .expect("accepted registry install should emit history");
    assert!(history.contains("\"status\":\"accepted\""));

    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::ModelLifecycle(receipt) => {
                    assert_eq!(receipt.tool_name, "model_registry__install");
                    assert_eq!(receipt.operation, ModelLifecycleOperationKind::Install);
                    assert_eq!(receipt.subject_kind, RegistrySubjectKind::Model);
                    assert_eq!(receipt.subject_id, "demo-model");
                    assert_eq!(
                        receipt.source_uri.as_deref(),
                        Some("https://models.example.com/demo.gguf")
                    );
                    assert!(receipt.success);
                    assert!(receipt.job_id.is_some());
                    assert!(receipt.error_class.is_none());
                    saw_receipt = true;
                }
                other => panic!("expected model lifecycle receipt, got {:?}", other),
            }
        }
    }

    assert!(saw_receipt, "expected typed acceptance receipt");
}

#[tokio::test(flavor = "current_thread")]
async fn native_dynamic_media_transcription_executes_and_emits_media_receipt() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime.clone(), Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "media__transcribe_audio",
        "arguments": {
            "audio_base64": "aGVsbG8=",
            "mime_type": "audio/wav",
            "language": "en"
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [10u8; 32],
        6,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("media transcription should be admitted natively");

    assert!(result.0);
    let history = result
        .1
        .expect("successful transcription should emit history");
    assert!(history.contains("kernel transcript"));

    let transcription_calls = runtime
        .transcription_calls
        .lock()
        .expect("transcription_calls mutex poisoned");
    assert_eq!(transcription_calls.as_slice(), ["audio/wav"]);
    drop(transcription_calls);

    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Media(receipt) => {
                    assert_eq!(receipt.tool_name, "media__transcribe_audio");
                    assert_eq!(
                        receipt.operation,
                        ioi_types::app::MediaOperationKind::Transcription
                    );
                    assert_eq!(receipt.output_mime_types, vec!["text/plain".to_string()]);
                    assert!(receipt.success);
                    saw_receipt = true;
                }
                other => panic!("expected media receipt, got {:?}", other),
            }
        }
    }

    assert!(saw_receipt, "expected media workload receipt");
}

#[tokio::test(flavor = "current_thread")]
async fn native_dynamic_media_speech_executes_and_emits_media_receipt() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime, Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "media__synthesize_speech",
        "arguments": {
            "text": "hello from the speech substrate",
            "mime_type": "audio/wav",
            "voice": "alloy"
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [11u8; 32],
        7,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("media speech synthesis should be admitted natively");

    assert!(result.0);
    let history = result
        .1
        .expect("successful speech synthesis should emit history");
    assert!(history.contains("\"mime_type\":\"audio/wav\""));
    assert!(history.contains("\"byte_count\":31"));

    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Media(receipt) => {
                    assert_eq!(receipt.tool_name, "media__synthesize_speech");
                    assert_eq!(
                        receipt.operation,
                        ioi_types::app::MediaOperationKind::SpeechSynthesis
                    );
                    assert_eq!(receipt.output_mime_types, vec!["audio/wav".to_string()]);
                    assert_eq!(receipt.output_bytes, Some(31));
                    assert!(receipt.success);
                    saw_receipt = true;
                }
                other => panic!("expected media receipt, got {:?}", other),
            }
        }
    }

    assert!(saw_receipt, "expected media workload receipt");
}

#[tokio::test(flavor = "current_thread")]
async fn native_dynamic_media_vision_executes_and_emits_media_receipt() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime, Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "media__vision_read",
        "arguments": {
            "image_base64": "aGVsbG8=",
            "mime_type": "image/png",
            "prompt": "inspect the screenshot"
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [12u8; 32],
        8,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("media vision should be admitted natively");

    assert!(result.0);
    let history = result
        .1
        .expect("successful vision read should emit history");
    assert!(history.contains("vision:image/png:inspect the screenshot"));

    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Media(receipt) => {
                    assert_eq!(receipt.tool_name, "media__vision_read");
                    assert_eq!(
                        receipt.operation,
                        ioi_types::app::MediaOperationKind::VisionRead
                    );
                    assert_eq!(receipt.output_mime_types, vec!["text/plain".to_string()]);
                    assert!(receipt.success);
                    saw_receipt = true;
                }
                other => panic!("expected media receipt, got {:?}", other),
            }
        }
    }

    assert!(saw_receipt, "expected media workload receipt");
}

#[tokio::test(flavor = "current_thread")]
async fn native_dynamic_media_image_generation_executes_and_emits_media_receipt() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime, Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "media__generate_image",
        "arguments": {
            "prompt": "paint a neon skyline",
            "mime_type": "image/png"
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [13u8; 32],
        9,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("media image generation should be admitted natively");

    assert!(result.0);
    let history = result
        .1
        .expect("successful image generation should emit history");
    assert!(history.contains("\"mime_type\":\"image/png\""));
    assert!(history.contains("\"byte_count\":20"));

    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Media(receipt) => {
                    assert_eq!(receipt.tool_name, "media__generate_image");
                    assert_eq!(
                        receipt.operation,
                        ioi_types::app::MediaOperationKind::ImageGeneration
                    );
                    assert_eq!(receipt.output_mime_types, vec!["image/png".to_string()]);
                    assert_eq!(receipt.output_bytes, Some(20));
                    assert!(receipt.success);
                    saw_receipt = true;
                }
                other => panic!("expected media receipt, got {:?}", other),
            }
        }
    }

    assert!(saw_receipt, "expected media workload receipt");
}

#[tokio::test(flavor = "current_thread")]
async fn native_dynamic_media_image_edit_executes_and_emits_media_receipt() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime, Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "media__edit_image",
        "arguments": {
            "source_image_base64": "aGVsbG8=",
            "source_mime_type": "image/png",
            "prompt": "sepia"
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [14u8; 32],
        10,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("media image edit should be admitted natively");

    assert!(result.0);
    let history = result.1.expect("successful image edit should emit history");
    assert!(history.contains("\"mime_type\":\"image/png\""));
    assert!(history.contains("\"byte_count\":5"));

    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Media(receipt) => {
                    assert_eq!(receipt.tool_name, "media__edit_image");
                    assert_eq!(
                        receipt.operation,
                        ioi_types::app::MediaOperationKind::ImageEdit
                    );
                    assert_eq!(receipt.output_mime_types, vec!["image/png".to_string()]);
                    assert_eq!(receipt.output_bytes, Some(5));
                    assert!(receipt.success);
                    saw_receipt = true;
                }
                other => panic!("expected media receipt, got {:?}", other),
            }
        }
    }

    assert!(saw_receipt, "expected media workload receipt");
}

#[tokio::test(flavor = "current_thread")]
async fn native_dynamic_media_video_generation_executes_and_emits_media_receipt() {
    let runtime = Arc::new(RecordingInferenceRuntime::default());
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let service = build_test_service(runtime, Some(tx));

    let dynamic_tool = serde_json::json!({
        "name": "media__generate_video",
        "arguments": {
            "prompt": "video prompt",
            "mime_type": "video/mp4",
            "duration_ms": 1800
        }
    });

    let result = super::handlers::handle_native_dynamic_tool(
        &service,
        &dynamic_tool,
        [15u8; 32],
        11,
        &test_agent_state(),
    )
    .await
    .expect("native handler should not fail transaction")
    .expect("media video generation should be admitted natively");

    assert!(result.0);
    let history = result
        .1
        .expect("successful video generation should emit history");
    assert!(history.contains("\"mime_type\":\"video/mp4\""));
    assert!(history.contains("\"byte_count\":12"));

    let mut saw_receipt = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Media(receipt) => {
                    assert_eq!(receipt.tool_name, "media__generate_video");
                    assert_eq!(
                        receipt.operation,
                        ioi_types::app::MediaOperationKind::VideoGeneration
                    );
                    assert_eq!(receipt.output_mime_types, vec!["video/mp4".to_string()]);
                    assert_eq!(receipt.output_bytes, Some(12));
                    assert!(receipt.success);
                    saw_receipt = true;
                }
                other => panic!("expected media receipt, got {:?}", other),
            }
        }
    }

    assert!(saw_receipt, "expected media workload receipt");
}

#[test]
fn workload_spec_check_fails_closed_when_capability_lease_missing() {
    let tool = AgentTool::FsRead {
        path: "README.md".to_string(),
    };
    let (mut spec, _) =
        super::build_workload_spec(&tool, &ActionTarget::FsRead, [8u8; 32], None, None, 1_000);
    spec.capability_lease = None;

    let check = spec.evaluate_lease(&ActionTarget::FsRead, None, 1_100);
    assert!(!check.satisfied);
    assert_eq!(check.reason.as_deref(), Some("missing_capability_lease"));
}
