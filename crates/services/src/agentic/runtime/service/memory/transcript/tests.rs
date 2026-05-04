use super::*;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::mock::MockInferenceRuntime;
use ioi_api::vm::inference::InferenceRuntime;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_memory::{ArchivalMemoryQuery, MemoryRuntime};
use ioi_types::app::action::ApprovalGrant;
use ioi_types::app::agentic::{
    InferenceOptions, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::app::{ActionRequest, ContextSlice};
use ioi_types::error::VmError;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::Instant;

fn sample_recorded_message() -> RecordedMessage {
    RecordedMessage {
        role: "user".to_string(),
        timestamp_ms: 123,
        trace_hash: None,
        raw_content: "raw secret: password=abc123".to_string(),
        scrubbed_for_model: "raw secret: [REDACTED_PII]".to_string(),
        scrubbed_for_scs: "raw secret: [REDACTED_PII]".to_string(),
        raw_reference: None,
        privacy_metadata: MessagePrivacyMetadata {
            redaction_version: "v1".to_string(),
            sensitive_fields_mask: vec!["pii".to_string()],
            policy_id: "desktop-agent/default".to_string(),
            policy_version: "1".to_string(),
            scrubbed_for_model_hash: None,
        },
    }
}

fn sample_agent_state(session_id: [u8; 32], goal: &str) -> AgentState {
    AgentState {
        session_id,
        goal: goal.to_string(),
        runtime_route_frame: None,
        transcript_root: [0u8; 32],
        status: crate::agentic::runtime::types::AgentStatus::Running,
        step_count: 3,
        max_steps: 32,
        last_action_type: None,
        parent_session_id: None,
        child_session_ids: Vec::new(),
        budget: 0,
        tokens_used: 0,
        consecutive_failures: 0,
        pending_approval: None::<ApprovalGrant>,
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
        tool_execution_log: BTreeMap::new(),
        execution_ledger: Default::default(),
        visual_som_map: None,
        visual_semantic_map: None,
        work_graph_context: None,
        target: None,
        resolved_intent: Some(ResolvedIntentState {
            intent_id: "browser.checkout".to_string(),
            scope: IntentScopeProfile::UiInteraction,
            band: IntentConfidenceBand::High,
            score: 0.98,
            top_k: Vec::new(),
            required_capabilities: Vec::new(),
            required_evidence: Vec::new(),
            success_conditions: Vec::new(),
            risk_class: String::new(),
            preferred_tier: "dom_headless".to_string(),
            intent_catalog_version: "test".to_string(),
            embedding_model_id: String::new(),
            embedding_model_version: String::new(),
            similarity_function_id: String::new(),
            intent_set_hash: [0u8; 32],
            tool_registry_hash: [0u8; 32],
            capability_ontology_hash: [0u8; 32],
            query_normalization_version: String::new(),
            intent_catalog_source_hash: [0u8; 32],
            evidence_requirements_hash: [0u8; 32],
            provider_selection: None,
            instruction_contract: None,
            constrained: false,
        }),
        awaiting_intent_clarification: false,
        working_directory: ".".to_string(),
        command_history: VecDeque::new(),
        active_lens: None,
    }
}

fn sample_perception_context() -> PerceptionContext {
    PerceptionContext {
        tier: crate::agentic::runtime::types::ExecutionTier::DomHeadless,
        screenshot_base64: None,
        visual_phash: [0u8; 32],
        active_window_title: "Chromium".to_string(),
        project_index: String::new(),
        agents_md_content: String::new(),
        memory_pointers: String::new(),
        available_tools: Vec::new(),
        tool_desc: String::new(),
        worker_assignment: None,
        visual_verification_note: None,
        last_failure_reason: None,
        consecutive_failures: 0,
    }
}

#[test]
fn decode_recorded_messages_for_model_surface() {
    let encoded_recorded =
        codec::to_bytes_canonical(&sample_recorded_message()).expect("recorded encode");
    let model_msg = decode_session_message(&encoded_recorded, false);
    assert!(model_msg.is_some());
    let model_msg = model_msg.expect("model decode");
    assert_eq!(model_msg.role, "user");
    assert_eq!(model_msg.content, "raw secret: [REDACTED_PII]");
}

#[test]
fn decode_recorded_message_prefers_raw_content_for_raw_surface() {
    let encoded_recorded =
        codec::to_bytes_canonical(&sample_recorded_message()).expect("recorded encode");
    let raw_msg = decode_session_message(&encoded_recorded, true);
    assert!(raw_msg.is_some());
    let raw_msg = raw_msg.expect("raw decode");
    assert_eq!(raw_msg.content, "raw secret: password=abc123");
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

fn build_test_service_without_memory_runtime_with_inference(
    inference: Arc<dyn InferenceRuntime>,
) -> RuntimeAgentService {
    let service = RuntimeAgentService::new(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        inference,
    );
    service
}

fn build_test_service_with_temp_memory_runtime_with_inference(
    inference: Arc<dyn InferenceRuntime>,
) -> (RuntimeAgentService, std::path::PathBuf) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_nanos());
    let path = std::env::temp_dir().join(format!("ioi_service_memory_runtime_tests_{ts}.db"));
    let memory_runtime =
        MemoryRuntime::open_sqlite(&path).expect("memory runtime should initialize");

    let service = RuntimeAgentService::new(
        Arc::new(NoopGuiDriver),
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        inference,
    )
    .with_memory_runtime(Arc::new(memory_runtime));

    (service, path)
}

struct SlowInferenceRuntime;

#[async_trait]
impl InferenceRuntime for SlowInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(b"[]".to_vec())
    }

    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        tokio::time::sleep(Duration::from_secs(30)).await;
        Ok(vec![0.0, 1.0, 2.0])
    }

    async fn load_model(
        &self,
        _model_hash: [u8; 32],
        _path: &std::path::Path,
    ) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

struct NoExecuteInferenceRuntime;

#[async_trait]
impl InferenceRuntime for NoExecuteInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        panic!("append_chat_to_scs must not call execute_inference");
    }

    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        Ok(vec![0.0, 1.0, 2.0])
    }

    async fn load_model(
        &self,
        _model_hash: [u8; 32],
        _path: &std::path::Path,
    ) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

struct NoInferenceRuntime;

#[async_trait]
impl InferenceRuntime for NoInferenceRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        panic!("append_chat_to_scs must not call execute_inference");
    }

    async fn embed_text(&self, _text: &str) -> Result<Vec<f32>, VmError> {
        panic!("append_chat_to_scs must not call embed_text for tool/system roles");
    }

    async fn load_model(
        &self,
        _model_hash: [u8; 32],
        _path: &std::path::Path,
    ) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

struct KeywordEmbeddingRuntime;

#[async_trait]
impl InferenceRuntime for KeywordEmbeddingRuntime {
    async fn execute_inference(
        &self,
        _model_hash: [u8; 32],
        _input_context: &[u8],
        _options: InferenceOptions,
    ) -> Result<Vec<u8>, VmError> {
        panic!("memory retrieval tests must not call execute_inference");
    }

    async fn embed_text(&self, text: &str) -> Result<Vec<f32>, VmError> {
        let normalized = text.to_ascii_lowercase();
        if normalized.contains("standup") || normalized.contains("2 pm") {
            Ok(vec![1.0, 0.0])
        } else if normalized.contains("calculator") {
            Ok(vec![0.0, 1.0])
        } else {
            Ok(vec![0.5, 0.5])
        }
    }

    async fn load_model(
        &self,
        _model_hash: [u8; 32],
        _path: &std::path::Path,
    ) -> Result<(), VmError> {
        Ok(())
    }

    async fn unload_model(&self, _model_hash: [u8; 32]) -> Result<(), VmError> {
        Ok(())
    }
}

#[tokio::test]
async fn append_and_hydrate_session_history_requires_memory_runtime() {
    let service = build_test_service_without_memory_runtime_with_inference(Arc::new(
        MockInferenceRuntime,
    ));
    let session_id = [11u8; 32];
    let msg = ChatMessage {
        role: "user".to_string(),
        content: "please use API_KEY=sk_live_123456789".to_string(),
        timestamp: 1_700_000_000_000u64,
        trace_hash: None,
    };

    let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
    assert!(append_res.is_err());

    let model_surface = service.hydrate_session_history(session_id);
    assert!(model_surface.is_err());

    let raw_surface = service.hydrate_session_history_raw(session_id);
    assert!(raw_surface.is_err());
}

#[tokio::test]
async fn append_and_hydrate_session_history_roundtrips_through_memory_runtime() {
    let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
        MockInferenceRuntime,
    ));
    let session_id = [12u8; 32];
    let msg = ChatMessage {
        role: "user".to_string(),
        content: "please use API_KEY=sk_live_987654321".to_string(),
        timestamp: 1_700_000_000_001u64,
        trace_hash: None,
    };

    let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
    assert!(append_res.is_ok());

    let model_surface = service.hydrate_session_history(session_id);
    assert!(model_surface.is_ok());
    let model_msgs = model_surface.expect("model hydration");
    assert_eq!(model_msgs.len(), 1);
    assert!(!model_msgs[0].content.contains("sk_live_987654321"));

    let raw_surface = service.hydrate_session_history_raw(session_id);
    assert!(raw_surface.is_ok());
    let raw_msgs = raw_surface.expect("raw hydration");
    assert_eq!(raw_msgs.len(), 1);
    assert!(raw_msgs[0].content.contains("sk_live_987654321"));

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn retrieve_context_hybrid_roundtrips_through_memory_runtime_archival_search() {
    let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
        KeywordEmbeddingRuntime,
    ));
    let session_id = [21u8; 32];

    let first = ChatMessage {
        role: "user".to_string(),
        content: "Tomorrow's standup is moved to 2 pm Eastern.".to_string(),
        timestamp: 1_700_000_000_010u64,
        trace_hash: None,
    };
    let second = ChatMessage {
        role: "user".to_string(),
        content: "Launch calculator and keep it pinned.".to_string(),
        timestamp: 1_700_000_000_011u64,
        trace_hash: None,
    };

    assert!(service
        .append_chat_to_scs(session_id, &first, 0)
        .await
        .is_ok());
    assert!(service
        .append_chat_to_scs(session_id, &second, 0)
        .await
        .is_ok());

    let retrieval = service
        .retrieve_context_hybrid_with_receipt("what changed about tomorrow's standup?", None)
        .await;

    assert!(retrieval.output.contains("standup"));
    assert!(retrieval.output.contains("[ID:"));
    let receipt = retrieval.receipt.expect("memory runtime receipt");
    assert_eq!(receipt.backend, "ioi-memory:hybrid-archival");
    assert!(receipt.success);
    assert_eq!(receipt.proof_ref, None);

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn append_chat_to_scs_enforces_semantic_indexing_budget() {
    let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
        SlowInferenceRuntime,
    ));
    let session_id = [33u8; 32];
    let seed_msg = ChatMessage {
        role: "user".to_string(),
        content: "Seed semantic history before timing assistant indexing.".to_string(),
        timestamp: 1_700_000_000_100u64,
        trace_hash: None,
    };
    let seed_res = service.append_chat_to_scs(session_id, &seed_msg, 0).await;
    assert!(seed_res.is_ok());

    let msg = ChatMessage {
        role: "assistant".to_string(),
        content: "This is long enough to trigger semantic fact extraction and embedding work."
            .to_string(),
        timestamp: 1_700_000_000_123u64,
        trace_hash: None,
    };

    let started = Instant::now();
    let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
    let elapsed = started.elapsed();

    assert!(append_res.is_ok());
    assert!(
        elapsed < SEMANTIC_INDEXING_BUDGET + Duration::from_secs(3),
        "append_chat_to_scs exceeded semantic indexing budget: {:?}",
        elapsed
    );

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn append_chat_to_scs_skips_semantic_indexing_for_structured_assistant_tool_calls() {
    let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
        NoInferenceRuntime,
    ));
    let session_id = [56u8; 32];
    let msg = ChatMessage {
        role: "assistant".to_string(),
        content: r#"{"name":"browser__click_at","arguments":{"x":63.0,"y":104.0}}"#
            .to_string(),
        timestamp: 1_700_000_000_791u64,
        trace_hash: None,
    };

    let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
    assert!(append_res.is_ok());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn append_chat_to_scs_avoids_execute_inference_for_fact_extraction() {
    let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
        NoExecuteInferenceRuntime,
    ));
    let session_id = [44u8; 32];
    let msg = ChatMessage {
        role: "tool".to_string(),
        content: "Tool Output (app__launch): Launched background process 'gnome-calculator' (PID: 555837)"
            .to_string(),
        timestamp: 1_700_000_000_456u64,
        trace_hash: None,
    };

    let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
    assert!(append_res.is_ok());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn append_chat_to_scs_skips_inference_for_tool_messages() {
    let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
        NoInferenceRuntime,
    ));
    let session_id = [55u8; 32];
    let msg = ChatMessage {
        role: "tool".to_string(),
        content: "Tool Output (app__launch): Launched background process 'calculator'"
            .to_string(),
        timestamp: 1_700_000_000_789u64,
        trace_hash: None,
    };

    let append_res = service.append_chat_to_scs(session_id, &msg, 0).await;
    assert!(append_res.is_ok());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn core_memory_updates_are_governed_and_prompt_ready() {
    let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
        MockInferenceRuntime,
    ));
    let session_id = [77u8; 32];
    let agent_state = sample_agent_state(session_id, "Complete checkout flow");
    let perception = sample_perception_context();
    let memory_runtime = service.memory_runtime.as_ref().expect("memory runtime");

    replace_core_memory_from_tool(
        memory_runtime,
        session_id,
        "workflow.stage",
        "Logged in and navigating to cart.",
    )
    .expect("replace workflow stage");
    append_core_memory_from_tool(
        memory_runtime,
        session_id,
        "workflow.notes",
        "Cart modal appears after clicking the top-right cart icon.",
    )
    .expect("append workflow notes");
    pin_core_memory_section(memory_runtime, session_id, "workflow.notes", true)
        .expect("pin workflow notes");

    let prompt_memory =
        prepare_prompt_memory_context(&service, session_id, &agent_state, &perception, None)
            .await
            .expect("prepare prompt memory");
    assert!(prompt_memory.contains("Current Goal: Complete checkout flow"));
    assert!(prompt_memory.contains("Workflow Stage: Logged in and navigating to cart."));
    assert!(prompt_memory.contains("Workflow Notes: Cart modal appears"));

    let rejected = replace_core_memory_from_tool(
        memory_runtime,
        session_id,
        "user.preferences.safe",
        "The password is hunter2",
    );
    assert!(rejected.is_err());

    let audits = memory_runtime
        .search_archival_memory(&ArchivalMemoryQuery {
            scope: MEMORY_RUNTIME_CORE_AUDIT_SCOPE.to_string(),
            thread_id: Some(session_id),
            text: "workflow.stage".to_string(),
            limit: 10,
        })
        .expect("load core audit records");
    assert!(!audits.is_empty());

    let _ = std::fs::remove_file(path);
}

#[test]
fn load_memory_session_status_exposes_core_memory_and_prompt_diagnostics() {
    let runtime = MemoryRuntime::open_sqlite_in_memory().expect("runtime");
    let session_id = [76u8; 32];

    replace_core_memory_from_tool(
        &runtime,
        session_id,
        "workflow.stage",
        "Reviewing the cart modal before checkout.",
    )
    .expect("replace core memory");
    persist_prompt_memory_diagnostics(
        &runtime,
        session_id,
        &MemoryPromptDiagnostics {
            updated_at_ms: 123,
            session_id_hex: hex::encode(session_id),
            total_chars: 400,
            prompt_hash: "prompt".to_string(),
            stable_prefix_hash: "stable".to_string(),
            dynamic_suffix_hash: "dynamic".to_string(),
            sections: vec![MemoryPromptSectionDiagnostic {
                name: "core_memory".to_string(),
                included: true,
                budget_chars: Some(500),
                original_chars: 120,
                rendered_chars: 120,
                truncated: false,
            }],
        },
    )
    .expect("persist prompt diagnostics");

    let status = load_memory_session_status(&runtime, session_id).expect("load session status");
    assert_eq!(status.session_id_hex, hex::encode(session_id));
    assert_eq!(status.core_sections.len(), 1);
    assert_eq!(status.core_sections[0].section, "workflow.stage");
    assert!(status.prompt_diagnostics.is_some());
    assert!(!status.core_audits.is_empty());
}

#[tokio::test]
async fn prepare_prompt_memory_context_persists_structured_ui_memory() {
    let (service, path) = build_test_service_with_temp_memory_runtime_with_inference(Arc::new(
        MockInferenceRuntime,
    ));
    let session_id = [78u8; 32];
    let agent_state = sample_agent_state(session_id, "Open cart modal");
    let perception = sample_perception_context();
    let snapshot = r#"
        <root>
          <window name="Shop">
            <dialog name="Cart">
              <button id="checkout">Checkout</button>
            </dialog>
          </window>
        </root>
    "#;

    let prompt_memory = prepare_prompt_memory_context(
        &service,
        session_id,
        &agent_state,
        &perception,
        Some(snapshot),
    )
    .await
    .expect("prepare prompt memory");
    assert!(prompt_memory.contains("Current Goal"));

    let memory_runtime = service.memory_runtime.as_ref().expect("memory runtime");
    let ui_records = memory_runtime
        .search_archival_memory(&ArchivalMemoryQuery {
            scope: MEMORY_RUNTIME_UI_SCOPE.to_string(),
            thread_id: Some(session_id),
            text: "Checkout".to_string(),
            limit: 10,
        })
        .expect("search ui memory");
    assert!(!ui_records.is_empty());
    assert!(ui_records[0].content.contains("Checkout"));

    let checkpoint_blob = memory_runtime
        .load_checkpoint_blob(session_id, MEMORY_RUNTIME_LAST_UI_SNAPSHOT_CHECKPOINT)
        .expect("load ui checkpoint");
    assert!(checkpoint_blob.is_some());

    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn enrichment_jobs_materialize_runtime_derived_records() {
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("runtime"));
    let session_id = [79u8; 32];
    let source_record_id = runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_TRANSCRIPT_SCOPE.to_string(),
            thread_id: Some(session_id),
            kind: "chat_message".to_string(),
            content: "Checkout Button opens the Cart Modal. Step 1. Click Checkout Button. Then confirm the order on the Dashboard.".to_string(),
            metadata_json: r#"{"trust_level":"runtime_observed"}"#.to_string(),
        })
        .expect("insert source")
        .expect("source id");
    assert!(enqueue_transcript_enrichment_jobs(
        &runtime,
        session_id,
        source_record_id
    ));

    let report = process_pending_memory_enrichment_jobs_once(
        runtime.clone(),
        Arc::new(KeywordEmbeddingRuntime),
        8,
    )
    .await
    .expect("process enrichment");
    assert!(report.claimed >= 1);
    assert!(report.completed >= 1);
    assert!(report.inserted_records >= 1);

    let facts = runtime
        .search_archival_memory(&ArchivalMemoryQuery {
            scope: MEMORY_RUNTIME_FACT_SCOPE.to_string(),
            thread_id: Some(session_id),
            text: "Checkout".to_string(),
            limit: 10,
        })
        .expect("search facts");
    assert!(!facts.is_empty());

    let status = load_memory_session_status(runtime.as_ref(), session_id).expect("status");
    let diagnostics = status
        .enrichment_diagnostics
        .expect("enrichment diagnostics");
    assert!(diagnostics.completed_jobs >= 1);
    assert!(diagnostics.inserted_records >= 1);
}

#[tokio::test]
async fn enrichment_diagnostics_track_secret_like_rejections() {
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("runtime"));
    let session_id = [80u8; 32];
    let source_record_id = runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_TRANSCRIPT_SCOPE.to_string(),
            thread_id: Some(session_id),
            kind: "chat_message".to_string(),
            content: "The password is hunter2 for the staging dashboard.".to_string(),
            metadata_json: r#"{"trust_level":"runtime_observed"}"#.to_string(),
        })
        .expect("insert source")
        .expect("source id");
    assert!(enqueue_transcript_enrichment_jobs(
        &runtime,
        session_id,
        source_record_id
    ));

    let report = process_pending_memory_enrichment_jobs_once(
        runtime.clone(),
        Arc::new(KeywordEmbeddingRuntime),
        8,
    )
    .await
    .expect("process enrichment");
    assert!(report.rejected_candidates >= 1);

    let status = load_memory_session_status(runtime.as_ref(), session_id).expect("status");
    let diagnostics = status
        .enrichment_diagnostics
        .expect("enrichment diagnostics");
    assert!(diagnostics.rejected_candidates >= 1);
    assert!(diagnostics
        .rejected_by_reason
        .contains_key("secret_like_content"));
}

#[tokio::test]
async fn ui_relationship_enrichment_materializes_control_context_records() {
    let runtime = Arc::new(MemoryRuntime::open_sqlite_in_memory().expect("runtime"));
    let session_id = [81u8; 32];
    let artifact_id = "desktop.ui.snapshot.test".to_string();
    runtime
        .upsert_artifact_json(
            session_id,
            &artifact_id,
            r#"{"kind":"ui_snapshot_xml","trust_level":"runtime_observed"}"#,
        )
        .expect("artifact metadata");
    runtime
        .put_artifact_blob(
            session_id,
            &artifact_id,
            br#"
                <root>
                  <window name="Shop">
                    <dialog name="Cart Modal">
                      <button id="checkout_button" name="Checkout" />
                    </dialog>
                  </window>
                </root>
            "#,
        )
        .expect("artifact blob");
    let source_record_id = runtime
        .insert_archival_record(&NewArchivalMemoryRecord {
            scope: MEMORY_RUNTIME_UI_SCOPE.to_string(),
            thread_id: Some(session_id),
            kind: "ui_observation".to_string(),
            content: "Window Shop URL https://example.test/cart Snapshot Hash abc".to_string(),
            metadata_json: r#"{"trust_level":"runtime_observed","active_window_title":"Shop","active_url":"https://example.test/cart","snapshot_hash":"abc"}"#.to_string(),
        })
        .expect("insert source")
        .expect("source id");

    assert!(enqueue_ui_enrichment_jobs(
        &runtime,
        session_id,
        source_record_id,
        &artifact_id
    ));
    let report = process_pending_memory_enrichment_jobs_once(
        runtime.clone(),
        Arc::new(KeywordEmbeddingRuntime),
        8,
    )
    .await
    .expect("process ui enrichment");
    assert!(report.inserted_records >= 1);
    let blob = runtime
        .load_artifact_blob(&artifact_id)
        .expect("load artifact")
        .expect("artifact blob");
    let source = runtime
        .load_archival_record(source_record_id)
        .expect("load source")
        .expect("source record");
    let extracted =
        extract_ui_relationship_candidates(&source, &String::from_utf8_lossy(&blob));
    assert!(extracted
        .iter()
        .any(|record| record.contains("Checkout") && record.contains("Cart Modal")));
}

#[test]
fn procedure_candidate_extractor_recognizes_inline_step_sequences() {
    let candidate = extract_procedure_candidate(
        "Checkout Button opens the Cart Modal. Step 1. Click Checkout Button. Then confirm the order on the Dashboard.",
    );
    assert!(candidate.is_some());
    let candidate = candidate.expect("procedure candidate");
    assert!(candidate.contains("Step 1"));
    assert!(candidate.contains("Then confirm"));
}
