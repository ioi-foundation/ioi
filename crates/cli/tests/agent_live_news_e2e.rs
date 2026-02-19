// Path: crates/cli/tests/agent_live_news_e2e.rs
#![cfg(all(feature = "consensus-admft", feature = "vm-wasm"))]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ioi_api::services::access::ServiceDirectory;
use ioi_api::services::BlockchainService;
use ioi_api::state::StateAccess;
use ioi_api::transaction::context::TxContext;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::inference::{HttpInferenceRuntime, InferenceRuntime};
use ioi_cli::testing::build_test_artifacts;
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::terminal::TerminalDriver;
use ioi_scs::{SovereignContextStore, StoreConfig};
use ioi_services::agentic::desktop::keys::AGENT_POLICY_PREFIX;
use ioi_services::agentic::desktop::service::step::helpers::default_safe_policy;
use ioi_services::agentic::desktop::{
    AgentMode, AgentState, AgentStatus, DesktopAgentService, StartAgentParams, StepAgentParams,
};
use ioi_state::primitives::hash::HashCommitmentScheme;
use ioi_state::tree::iavl::IAVLTree;
use ioi_types::app::agentic::{
    InferenceOptions, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};
use ioi_types::app::{ActionRequest, ContextSlice, KernelEvent, WorkloadReceipt};
use ioi_types::{codec, error::VmError};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::tempdir;
use tokio::sync::broadcast;

use image::{ImageBuffer, ImageFormat, Rgba};

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
        Ok(())
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }
}

#[derive(Debug, Deserialize)]
struct ArbiterVerdict {
    pass: bool,
    confidence: String,
    rationale: String,
    #[serde(default)]
    failures: Vec<String>,
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
        intent_id: "web.research".to_string(),
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
    let scs_path = temp_dir.path().join("live_news.scs");
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

fn drain_events(rx: &mut broadcast::Receiver<KernelEvent>, sink: &mut Vec<KernelEvent>) {
    while let Ok(event) = rx.try_recv() {
        sink.push(event);
    }
}

fn extract_urls(text: &str) -> BTreeSet<String> {
    text.split_whitespace()
        .filter_map(|token| {
            let trimmed = token
                .trim_matches(|ch: char| ",.;:!?()[]}\"'".contains(ch))
                .trim();
            if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
                Some(trimmed.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn month_name_present(text_lc: &str) -> bool {
    [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ]
    .iter()
    .any(|m| text_lc.contains(m))
}

fn contains_iso_date(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 10 {
        return false;
    }
    for i in 0..=bytes.len() - 10 {
        let slice = &bytes[i..i + 10];
        let ok = slice[0].is_ascii_digit()
            && slice[1].is_ascii_digit()
            && slice[2].is_ascii_digit()
            && slice[3].is_ascii_digit()
            && slice[4] == b'-'
            && slice[5].is_ascii_digit()
            && slice[6].is_ascii_digit()
            && slice[7] == b'-'
            && slice[8].is_ascii_digit()
            && slice[9].is_ascii_digit();
        if ok {
            return true;
        }
    }
    false
}

fn contains_year(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|part| part.len() == 4)
        .any(|year| matches!(year.parse::<u32>(), Ok(v) if (1900..=2100).contains(&v)))
}

fn contains_absolute_date(text: &str) -> bool {
    let lc = text.to_ascii_lowercase();
    contains_iso_date(text) || (month_name_present(&lc) && contains_year(text))
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
}

fn requires_human_intervention(reason: &str) -> bool {
    let lower = reason.to_ascii_lowercase();
    lower.contains("waiting for approval")
        || lower.contains("sudo password")
        || lower.contains("clarification")
        || lower.contains("human verification")
        || lower.contains("waiting for user intervention")
}

fn truncate_for_log(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        return compact;
    }
    compact.chars().take(max_chars).collect::<String>() + "..."
}

fn summarize_recent_events(events: &[KernelEvent], limit: usize) -> String {
    if events.is_empty() {
        return "(no events captured)".to_string();
    }

    let mut lines = Vec::new();
    for event in events.iter().rev().take(limit).rev() {
        let line = match event {
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => format!(
                "action tool={} status={} output={}",
                tool_name,
                agent_status,
                truncate_for_log(output, 160)
            ),
            KernelEvent::RoutingReceipt(receipt) => format!(
                "routing tool={} decision={} success={} failure_class={} escalation={:?} checks={}",
                receipt.tool_name,
                receipt.policy_decision,
                receipt.post_state.success,
                receipt.failure_class_name,
                receipt.escalation_path,
                truncate_for_log(&receipt.post_state.verification_checks.join(","), 1000)
            ),
            KernelEvent::WorkloadReceipt(workload) => match &workload.receipt {
                WorkloadReceipt::WebRetrieve(web) => format!(
                    "workload web tool={} backend={} success={} sources={} docs={} error_class={}",
                    web.tool_name,
                    web.backend,
                    web.success,
                    web.sources_count,
                    web.documents_count,
                    web.error_class.as_deref().unwrap_or("none")
                ),
                _ => "workload other".to_string(),
            },
            KernelEvent::AgentStep(trace) => format!(
                "trace step={} success={} error={} output={}",
                trace.step_index,
                trace.success,
                trace.error.as_deref().unwrap_or("none"),
                truncate_for_log(&trace.raw_output, 220)
            ),
            KernelEvent::IntentResolutionReceipt(receipt) => {
                format!("intent scope={:?} band={:?}", receipt.scope, receipt.band)
            }
            _ => "event(other)".to_string(),
        };
        lines.push(line);
    }
    lines.join("\n")
}

async fn run_arbiter(
    runtime: Arc<dyn InferenceRuntime>,
    payload: &serde_json::Value,
) -> Result<ArbiterVerdict> {
    let prompt = format!(
        "You are an impartial e2e arbiter. Respond with JSON only: \
{{\"pass\":bool,\"confidence\":\"high|medium|low\",\"rationale\":string,\"failures\":[string]}}.\n\
Decide pass=true only if the answer is plausible breaking-news synthesis, reflects recency, and uses sources/dates correctly.\n\
Treat `run_timestamp_ms` in the payload as the authoritative runtime clock. \
Do not fail solely because a date appears \"in the future\" relative to your internal assumptions.\n\
Payload:\n{}",
        serde_json::to_string_pretty(payload)?
    );

    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.0,
        json_mode: true,
        max_tokens: 600,
    };
    let raw = runtime
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
        .map_err(|e| anyhow!("arbiter inference failed: {}", e))?;
    let text = String::from_utf8(raw).map_err(|_| anyhow!("arbiter response was not UTF-8"))?;
    let json_text = extract_json_object(&text)
        .ok_or_else(|| anyhow!("arbiter did not return JSON object: {}", text))?;
    let verdict: ArbiterVerdict = serde_json::from_str(json_text)
        .map_err(|e| anyhow!("failed to parse arbiter verdict: {} raw={}", e, text))?;
    Ok(verdict)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live internet + external inference required"]
async fn live_breaking_news_chat_reply_e2e() -> Result<()> {
    build_test_artifacts();

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let arbiter_model =
        std::env::var("NEWS_E2E_ARBITER_MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string());
    let api_url = "https://api.openai.com/v1/chat/completions".to_string();

    let agent_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url.clone(),
        openai_api_key.clone(),
        openai_model,
    ));
    let arbiter_runtime: Arc<dyn InferenceRuntime> = Arc::new(HttpInferenceRuntime::new(
        api_url,
        openai_api_key,
        arbiter_model,
    ));

    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs()?;
    let service = DesktopAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        agent_runtime.clone(),
        agent_runtime,
    )
    .with_scs(Arc::new(Mutex::new(scs)))
    .with_event_sender(event_tx);

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let services_dir = ServiceDirectory::new(vec![]);
    let mut ctx = build_ctx(&services_dir);
    let session_id = [0x42u8; 32];
    let query =
        "what's the latest breaking news? provide a chat reply with citations and absolute dates";

    let start_params = StartAgentParams {
        session_id,
        goal: query.to_string(),
        max_steps: 16,
        parent_session_id: None,
        initial_budget: 4000,
        mode: AgentMode::Agent,
    };
    service
        .handle_service_call(
            &mut state,
            "start@v1",
            &codec::to_bytes_canonical(&start_params)
                .map_err(|e| anyhow!("failed to encode start params: {}", e))?,
            &mut ctx,
        )
        .await?;
    enable_intent_shadow_mode(&mut state, session_id);
    seed_resolved_intent(&mut state, session_id, IntentScopeProfile::WebResearch);

    let started = Instant::now();
    let deadline = Duration::from_secs(60);
    let mut captured_events: Vec<KernelEvent> = Vec::new();

    loop {
        drain_events(&mut event_rx, &mut captured_events);
        let current = read_agent_state(&state, session_id);
        if matches!(current.status, AgentStatus::Completed(_))
            || matches!(current.status, AgentStatus::Failed(_))
        {
            break;
        }
        if started.elapsed() > deadline {
            break;
        }
        match &current.status {
            AgentStatus::Running => {}
            AgentStatus::Paused(reason) => {
                if requires_human_intervention(reason) {
                    return Err(anyhow!(
                        "agent paused and requires user intervention: {}\nrecent_events:\n{}",
                        reason,
                        summarize_recent_events(&captured_events, 24)
                    ));
                }
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                return Err(anyhow!(
                    "agent entered unexpected non-terminal status: {:?}",
                    current.status
                ));
            }
            AgentStatus::Completed(_) | AgentStatus::Failed(_) => {}
        }
        service
            .handle_service_call(
                &mut state,
                "step@v1",
                &codec::to_bytes_canonical(&StepAgentParams { session_id })
                    .map_err(|e| anyhow!("failed to encode step params: {}", e))?,
                &mut ctx,
            )
            .await?;
    }
    drain_events(&mut event_rx, &mut captured_events);

    let elapsed = started.elapsed();
    let final_state = read_agent_state(&state, session_id);
    if elapsed > deadline {
        return Err(anyhow!(
            "live news e2e exceeded SLA: elapsed={}ms final_status={:?}\nrecent_events:\n{}",
            elapsed.as_millis(),
            final_state.status,
            summarize_recent_events(&captured_events, 16)
        ));
    }
    if !matches!(final_state.status, AgentStatus::Completed(_)) {
        return Err(anyhow!(
            "agent did not complete successfully; final status={:?}\nrecent_events:\n{}",
            final_state.status,
            summarize_recent_events(&captured_events, 16)
        ));
    }

    let mut saw_terminal_chat_reply = false;
    let mut final_reply = String::new();
    let mut saw_web_routing = false;
    let mut saw_web_retrieve_receipt = false;
    let mut evidence = Vec::new();

    for event in &captured_events {
        match event {
            KernelEvent::AgentActionResult {
                tool_name,
                output,
                agent_status,
                ..
            } => {
                if tool_name == "chat__reply" && agent_status.eq_ignore_ascii_case("completed") {
                    saw_terminal_chat_reply = true;
                    final_reply = output.clone();
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    if matches!(web.tool_name.as_str(), "web__search" | "web__read") {
                        saw_web_retrieve_receipt = true;
                        evidence.push(format!(
                            "workload:{} success={} sources={} documents={}",
                            web.tool_name, web.success, web.sources_count, web.documents_count
                        ));
                    }
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                if matches!(receipt.tool_name.as_str(), "web__search" | "web__read") {
                    saw_web_routing = true;
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
                }
            }
            _ => {}
        }
    }

    if !saw_terminal_chat_reply {
        return Err(anyhow!(
            "deterministic check failed: terminal chat__reply was not observed; final_status={:?}\nrecent_events:\n{}",
            final_state.status,
            summarize_recent_events(&captured_events, 24)
        ));
    }
    if final_reply.trim().is_empty() {
        return Err(anyhow!(
            "deterministic check failed: terminal chat__reply output was empty"
        ));
    }

    let urls = extract_urls(&final_reply);
    if urls.len() < 2 {
        return Err(anyhow!(
            "deterministic check failed: expected at least 2 distinct source URLs, got {}. reply={}",
            urls.len(),
            final_reply
        ));
    }
    if !contains_absolute_date(&final_reply) {
        return Err(anyhow!(
            "deterministic check failed: final reply missing absolute dates. reply={}",
            final_reply
        ));
    }
    if !(saw_web_routing || saw_web_retrieve_receipt) {
        return Err(anyhow!(
            "deterministic check failed: no web retrieval evidence found in routing/workload events"
        ));
    }

    let deterministic_payload = json!({
        "terminal_chat_reply_observed": saw_terminal_chat_reply,
        "elapsed_ms": elapsed.as_millis(),
        "source_url_count": urls.len(),
        "has_absolute_date": contains_absolute_date(&final_reply),
        "has_web_evidence": saw_web_routing || saw_web_retrieve_receipt,
    });
    let arbiter_payload = json!({
        "query": query,
        "run_timestamp_ms": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
        "deterministic": deterministic_payload,
        "final_reply": final_reply,
        "source_urls": urls,
        "event_evidence": evidence,
    });
    println!(
        "LIVE_NEWS_E2E_ARBITER_INPUT={}",
        serde_json::to_string_pretty(&arbiter_payload)?
    );

    let verdict = match run_arbiter(arbiter_runtime, &arbiter_payload).await {
        Ok(verdict) => verdict,
        Err(err) => ArbiterVerdict {
            pass: true,
            confidence: "low".to_string(),
            rationale: format!(
                "LLM arbiter unavailable; deterministic checks passed. fallback_reason={}",
                err
            ),
            failures: vec!["llm_arbiter_unavailable".to_string()],
        },
    };
    println!(
        "LIVE_NEWS_E2E_ARBITER_VERDICT={}",
        serde_json::to_string_pretty(&json!({
            "pass": verdict.pass,
            "confidence": verdict.confidence,
            "rationale": verdict.rationale,
            "failures": verdict.failures,
        }))?
    );

    if !verdict.pass {
        return Err(anyhow!(
            "arbiter failed live news response: confidence={} rationale={} failures={}",
            verdict.confidence,
            verdict.rationale,
            verdict.failures.join("; ")
        ));
    }

    Ok(())
}
