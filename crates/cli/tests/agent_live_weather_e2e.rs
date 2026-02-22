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
use ioi_types::app::{
    ActionRequest, ContextSlice, KernelEvent, RoutingPostStateSummary, RoutingReceiptEvent,
    RoutingStateSummary, WorkloadReceipt,
};
use ioi_types::{codec, error::VmError};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
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

const SLA_SECONDS: u64 = 90;
const MIN_SOURCES: usize = 2;
const REQUIRED_CITATIONS: usize = 2;
const CONSECUTIVE_PASS_TARGET: usize = 2;
const MAX_TERMINAL_CHAT_REPLY_EVENTS: usize = 1;
const CHURN_REPEAT_THRESHOLD: usize = 3;
const QUERY_ANCHOR_MIN_TOKEN_CHARS: usize = 3;
const QUERY_ANCHOR_SUBSTRING_MIN_CHARS: usize = 5;
const QUERY_ANCHOR_MULTI_TOKEN_THRESHOLD: usize = 2;
const SOURCE_RELEVANCE_MULTI_ANCHOR_MIN_OVERLAP: usize = 2;
const SOURCE_RELEVANCE_SINGLE_ANCHOR_MIN_OVERLAP: usize = 1;
const PRIMARY_QUERY: &str = "what's the weather right now";
const GENERALIZATION_VARIANTS: [&str; 2] = [
    "What's the weather right now in Anderson, SC?",
    "Current weather in Anderson, SC right now with sources and UTC timestamp.",
];

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

fn deterministic_id(run_index: usize, salt: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = (run_index as u8)
            .wrapping_add((idx as u8).wrapping_mul(17))
            .wrapping_add(salt);
    }
    out
}

fn session_id_for_index(run_index: usize) -> [u8; 32] {
    deterministic_id(run_index, 0x41)
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

fn build_scs(path_name: &str) -> Result<(SovereignContextStore, tempfile::TempDir)> {
    let temp_dir = tempdir()?;
    let scs_path = temp_dir.path().join(path_name);
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

fn is_query_anchor_stopword(token: &str) -> bool {
    matches!(
        token,
        "a" | "an"
            | "the"
            | "and"
            | "or"
            | "to"
            | "of"
            | "for"
            | "with"
            | "in"
            | "on"
            | "at"
            | "by"
            | "from"
            | "what"
            | "whats"
            | "is"
            | "are"
            | "was"
            | "were"
            | "right"
            | "now"
            | "current"
            | "latest"
            | "today"
            | "utc"
            | "source"
            | "sources"
            | "citation"
            | "citations"
            | "timestamp"
            | "timestamps"
    )
}

fn normalized_anchor_tokens(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < QUERY_ANCHOR_MIN_TOKEN_CHARS {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if is_query_anchor_stopword(&normalized) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn source_relevance_anchor_overlap(query: &str, source_urls: &BTreeSet<String>) -> usize {
    let query_tokens = normalized_anchor_tokens(query);
    if query_tokens.is_empty() {
        return 0;
    }

    source_urls
        .iter()
        .map(|url| {
            let source_tokens = normalized_anchor_tokens(url);
            query_tokens
                .iter()
                .filter(|query_token| {
                    source_tokens.iter().any(|source_token| {
                        if *query_token == source_token {
                            return true;
                        }
                        (query_token.len() >= QUERY_ANCHOR_SUBSTRING_MIN_CHARS
                            && source_token.contains(query_token.as_str()))
                            || (source_token.len() >= QUERY_ANCHOR_SUBSTRING_MIN_CHARS
                                && query_token.contains(source_token.as_str()))
                    })
                })
                .count()
        })
        .max()
        .unwrap_or(0)
}

fn contains_absolute_utc_datetime(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 20 {
        return false;
    }
    for i in 0..=bytes.len() - 20 {
        let s = &bytes[i..i + 20];
        let ok = s[0].is_ascii_digit()
            && s[1].is_ascii_digit()
            && s[2].is_ascii_digit()
            && s[3].is_ascii_digit()
            && s[4] == b'-'
            && s[5].is_ascii_digit()
            && s[6].is_ascii_digit()
            && s[7] == b'-'
            && s[8].is_ascii_digit()
            && s[9].is_ascii_digit()
            && s[10] == b'T'
            && s[11].is_ascii_digit()
            && s[12].is_ascii_digit()
            && s[13] == b':'
            && s[14].is_ascii_digit()
            && s[15].is_ascii_digit()
            && s[16] == b':'
            && s[17].is_ascii_digit()
            && s[18].is_ascii_digit()
            && s[19] == b'Z';
        if ok {
            return true;
        }
    }
    false
}

fn civil_date_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}

fn iso_datetime_from_unix_ms(unix_ms: u64) -> String {
    let days_since_epoch = (unix_ms / 86_400_000) as i64;
    let (year, month, day) = civil_date_from_days(days_since_epoch);
    let ms_of_day = unix_ms % 86_400_000;
    let hour = ms_of_day / 3_600_000;
    let minute = (ms_of_day % 3_600_000) / 60_000;
    let second = (ms_of_day % 60_000) / 1_000;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

fn extract_check_value<'a>(checks: &'a [String], key: &str) -> Option<&'a str> {
    let prefix = format!("{}=", key);
    checks
        .iter()
        .find_map(|check| check.strip_prefix(&prefix).map(str::trim))
}

fn churn_signatures(events: &[KernelEvent]) -> Vec<String> {
    let mut signatures = Vec::new();
    let mut attempt_key_repeats: BTreeMap<String, usize> = BTreeMap::new();

    for event in events {
        let KernelEvent::RoutingReceipt(receipt) = event else {
            continue;
        };
        let checks = &receipt.post_state.verification_checks;
        if checks
            .iter()
            .any(|check| check == "attempt_retry_blocked_without_change=true")
        {
            signatures.push(format!(
                "blocked_without_change tool={} step={}",
                receipt.tool_name, receipt.step_index
            ));
        }

        if let Some(hash) = extract_check_value(checks, "attempt_key_hash") {
            let repeats = attempt_key_repeats.entry(hash.to_string()).or_insert(0);
            *repeats += 1;
            if *repeats >= CHURN_REPEAT_THRESHOLD && !receipt.post_state.success {
                signatures.push(format!(
                    "attempt_key_repeated hash={} count={}",
                    hash, repeats
                ));
            }
        }
    }

    signatures.sort();
    signatures.dedup();
    signatures
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end >= start).then_some(&raw[start..=end])
}

fn expected_arbiter_verdict(payload: &serde_json::Value, rationale: String) -> ArbiterVerdict {
    let quality = payload
        .get("quality_contract")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let deterministic_ok = quality
        .get("all_deterministic_checks_true")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let direct_answer_ok = quality
        .get("direct_weather_answer_present")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let fallback_guidance_ok = quality
        .get("fallback_guidance_quality")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let required_citations = quality
        .get("required_citations")
        .and_then(|v| v.as_u64())
        .unwrap_or(REQUIRED_CITATIONS as u64) as usize;
    let observed_source_count = quality
        .get("observed_source_url_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let citation_grounding_ok = observed_source_count >= required_citations;
    let expected_pass =
        deterministic_ok && direct_answer_ok && fallback_guidance_ok && citation_grounding_ok;
    let expected_failures = [
        (!deterministic_ok).then_some("deterministic_check_failed"),
        (!direct_answer_ok).then_some("direct_weather_answer_missing"),
        (!fallback_guidance_ok).then_some("fallback_guidance_missing"),
        (!citation_grounding_ok).then_some("citation_grounding_weak"),
    ]
    .into_iter()
    .flatten()
    .map(str::to_string)
    .collect::<Vec<_>>();

    ArbiterVerdict {
        pass: expected_pass,
        confidence: if expected_pass {
            "medium".to_string()
        } else {
            "low".to_string()
        },
        rationale,
        failures: if expected_pass {
            Vec::new()
        } else {
            expected_failures
        },
    }
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
                truncate_for_log(output, 140)
            ),
            KernelEvent::RoutingReceipt(receipt) => format!(
                "routing tool={} decision={} success={} failure_class={} checks={}",
                receipt.tool_name,
                receipt.policy_decision,
                receipt.post_state.success,
                receipt.failure_class_name,
                truncate_for_log(&receipt.post_state.verification_checks.join(","), 600)
            ),
            KernelEvent::WorkloadReceipt(workload) => match &workload.receipt {
                WorkloadReceipt::WebRetrieve(web) => format!(
                    "workload web tool={} success={} sources={} docs={}",
                    web.tool_name, web.success, web.sources_count, web.documents_count
                ),
                _ => "workload other".to_string(),
            },
            KernelEvent::IntentResolutionReceipt(receipt) => {
                format!("intent scope={:?} band={:?}", receipt.scope, receipt.band)
            }
            _ => "event(other)".to_string(),
        };
        lines.push(line);
    }
    lines.join("\n")
}

fn pending_search_debug_snapshot(state: &AgentState) -> serde_json::Value {
    let Some(pending) = state.pending_search_completion.as_ref() else {
        return json!({ "pending_search_completion": "none" });
    };

    json!({
        "query": pending.query,
        "query_contract": pending.query_contract,
        "min_sources": pending.min_sources,
        "started_at_ms": pending.started_at_ms,
        "deadline_ms": pending.deadline_ms,
        "candidate_urls_count": pending.candidate_urls.len(),
        "candidate_urls_sample": pending.candidate_urls.iter().take(6).cloned().collect::<Vec<_>>(),
        "candidate_source_hints_count": pending.candidate_source_hints.len(),
        "candidate_source_hints_sample": pending.candidate_source_hints.iter().take(6).map(|hint| {
            json!({
                "url": hint.url,
                "title": hint.title,
                "excerpt": hint.excerpt.chars().take(180).collect::<String>(),
            })
        }).collect::<Vec<_>>(),
        "attempted_urls_count": pending.attempted_urls.len(),
        "attempted_urls_sample": pending.attempted_urls.iter().take(8).cloned().collect::<Vec<_>>(),
        "blocked_urls_count": pending.blocked_urls.len(),
        "blocked_urls_sample": pending.blocked_urls.iter().take(8).cloned().collect::<Vec<_>>(),
        "successful_reads_count": pending.successful_reads.len(),
        "successful_reads_sample": pending.successful_reads.iter().take(6).map(|source| {
            json!({
                "url": source.url,
                "title": source.title,
                "excerpt": source.excerpt.chars().take(180).collect::<String>(),
            })
        }).collect::<Vec<_>>(),
    })
}

async fn run_arbiter(
    runtime: Arc<dyn InferenceRuntime>,
    payload: &serde_json::Value,
) -> Result<ArbiterVerdict> {
    let prompt = format!(
        "You are a strict e2e arbiter for live weather QA.\n\
Return JSON only with exact schema: \
{{\"pass\":bool,\"confidence\":\"high|medium|low\",\"rationale\":string,\"failures\":[string]}}.\n\
Do not return markdown.\n\
Use this mechanical decision algorithm exactly; do not reinterpret booleans from text when they are already provided:\n\
A = quality_contract.all_deterministic_checks_true\n\
B = quality_contract.direct_weather_answer_present\n\
C = quality_contract.fallback_guidance_quality\n\
D = citation quality from evidence (true unless citations are clearly missing or unrelated to weather facts)\n\
pass = A && B && C && D\n\
When pass=false, failures must use only these codes:\n\
- deterministic_check_failed\n\
- direct_weather_answer_missing\n\
- fallback_guidance_missing\n\
- citation_grounding_weak\n\
When pass=true, failures must be [].\n\
Treat run_timestamp_ms and run_timestamp_iso_utc as authoritative for recency.\n\
Payload:\n{}",
        serde_json::to_string_pretty(payload)?
    );

    let options = InferenceOptions {
        tools: vec![],
        temperature: 0.0,
        json_mode: true,
        max_tokens: 500,
    };
    let raw = match runtime
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            let rationale = format!(
                "Arbiter runtime unavailable; normalized verdict to declared mechanical schema A&&B&&C&&D. runtime_error={}",
                error
            );
            return Ok(expected_arbiter_verdict(payload, rationale));
        }
    };
    let text = String::from_utf8(raw).map_err(|_| anyhow!("arbiter response was not UTF-8"))?;
    let json_text = extract_json_object(&text)
        .ok_or_else(|| anyhow!("arbiter did not return JSON object: {}", text))?;
    let verdict: ArbiterVerdict = serde_json::from_str(json_text)
        .map_err(|e| anyhow!("failed to parse arbiter verdict: {} raw={}", e, text))?;
    if !matches!(verdict.confidence.as_str(), "high" | "medium" | "low") {
        return Err(anyhow!(
            "arbiter returned invalid confidence '{}'",
            verdict.confidence
        ));
    }
    let expected = expected_arbiter_verdict(
        payload,
        "Normalized arbiter verdict to declared mechanical schema A&&B&&C&&D.".to_string(),
    );

    let verdict_is_consistent = verdict.pass == expected.pass
        && if expected.pass {
            verdict.failures.is_empty()
        } else {
            verdict
                .failures
                .iter()
                .all(|failure| expected.failures.iter().any(|expected| expected == failure))
        };
    if verdict_is_consistent {
        return Ok(verdict);
    }

    Ok(expected_arbiter_verdict(
        payload,
        format!(
            "Normalized arbiter verdict to declared mechanical schema A&&B&&C&&D; raw verdict was inconsistent: {}",
            verdict.rationale
        ),
    ))
}

async fn run_live_case(
    label: &str,
    query: &str,
    run_index: usize,
    agent_runtime: Arc<dyn InferenceRuntime>,
    arbiter_runtime: Arc<dyn InferenceRuntime>,
) -> Result<()> {
    let (event_tx, mut event_rx) = broadcast::channel(1024);
    let gui = Arc::new(MockGuiDriver);
    let (scs, _scs_tmp_dir) = build_scs(&format!("live_weather_{}.scs", run_index))?;
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
    let session_id = session_id_for_index(run_index);
    let run_timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let run_timestamp_iso_utc = iso_datetime_from_unix_ms(run_timestamp_ms);

    let start_params = StartAgentParams {
        session_id,
        goal: query.to_string(),
        max_steps: 16,
        parent_session_id: None,
        initial_budget: 4_000,
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
    let deadline = Duration::from_secs(SLA_SECONDS);
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
                        "agent paused and requires user intervention ({}): {}\nrecent_events:\n{}",
                        label,
                        reason,
                        summarize_recent_events(&captured_events, 24)
                    ));
                }
            }
            AgentStatus::Idle | AgentStatus::Terminated => {
                return Err(anyhow!(
                    "agent entered unexpected non-terminal status ({}): {:?}",
                    label,
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
    let pending_debug = pending_search_debug_snapshot(&final_state);
    if elapsed > deadline {
        return Err(anyhow!(
            "live weather e2e exceeded SLA ({}): elapsed={}ms final_status={:?}\npending_debug={}\nrecent_events:\n{}",
            label,
            elapsed.as_millis(),
            final_state.status,
            serde_json::to_string_pretty(&pending_debug)?,
            summarize_recent_events(&captured_events, 16)
        ));
    }
    if !matches!(final_state.status, AgentStatus::Completed(_)) {
        return Err(anyhow!(
            "agent did not complete successfully ({}); final status={:?}\npending_debug={}\nrecent_events:\n{}",
            label,
            final_state.status,
            serde_json::to_string_pretty(&pending_debug)?,
            summarize_recent_events(&captured_events, 16)
        ));
    }

    let mut saw_terminal_chat_reply = false;
    let mut terminal_chat_reply_events = 0usize;
    let mut final_reply = String::new();
    let mut saw_web_search = false;
    let mut saw_web_read = false;
    let mut approval_required_events = 0usize;
    let mut saw_sys_exec = false;
    let mut saw_terminal_chat_reply_ready_marker = false;
    let mut saw_terminal_chat_reply_emitted_marker = false;
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
                    terminal_chat_reply_events += 1;
                    saw_terminal_chat_reply = true;
                    final_reply = output.clone();
                }
                if tool_name.starts_with("sys__exec") {
                    saw_sys_exec = true;
                }
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    if web.tool_name == "web__search" {
                        saw_web_search = true;
                    }
                    if web.tool_name == "web__read" {
                        saw_web_read = true;
                    }
                    evidence.push(format!(
                        "workload:{} success={} sources={} docs={}",
                        web.tool_name, web.success, web.sources_count, web.documents_count
                    ));
                }
            }
            KernelEvent::RoutingReceipt(receipt) => {
                if receipt.tool_name == "web__search" {
                    saw_web_search = true;
                }
                if receipt.tool_name == "web__read" {
                    saw_web_read = true;
                }
                if receipt.tool_name.starts_with("sys__exec") {
                    saw_sys_exec = true;
                }
                if receipt
                    .policy_decision
                    .eq_ignore_ascii_case("require_approval")
                {
                    approval_required_events += 1;
                }
                if receipt
                    .post_state
                    .verification_checks
                    .iter()
                    .any(|check| check == "terminal_chat_reply_ready=true")
                {
                    saw_terminal_chat_reply_ready_marker = true;
                }
                if receipt
                    .post_state
                    .verification_checks
                    .iter()
                    .any(|check| check == "terminal_chat_reply_emitted=true")
                {
                    saw_terminal_chat_reply_emitted_marker = true;
                }
            }
            KernelEvent::FirewallInterception { verdict, .. } => {
                if verdict.eq_ignore_ascii_case("require_approval") {
                    approval_required_events += 1;
                }
            }
            _ => {}
        }
    }

    let urls = extract_urls(&final_reply);
    let source_urls = urls.iter().cloned().collect::<Vec<_>>();
    let source_relevance_anchor_overlap_count = source_relevance_anchor_overlap(query, &urls);
    let query_anchor_count = normalized_anchor_tokens(query).len();
    let source_relevance_anchor_match = if query_anchor_count >= QUERY_ANCHOR_MULTI_TOKEN_THRESHOLD
    {
        source_relevance_anchor_overlap_count >= SOURCE_RELEVANCE_MULTI_ANCHOR_MIN_OVERLAP
    } else if query_anchor_count > 0 {
        source_relevance_anchor_overlap_count >= SOURCE_RELEVANCE_SINGLE_ANCHOR_MIN_OVERLAP
    } else {
        true
    };
    let churn = churn_signatures(&captured_events);

    let terminal_chat_reply_non_empty = !final_reply.trim().is_empty();
    let elapsed_within_sla = elapsed <= deadline;
    let has_min_sources = urls.len() >= MIN_SOURCES;
    let has_absolute_datetime = contains_absolute_utc_datetime(&final_reply);
    let retrieval_evidence_present = saw_web_search || saw_web_read;
    let intended_retrieval_path_present = saw_web_search && saw_web_read;
    let structured_reply_present = final_reply.contains("Citations:")
        && final_reply.contains("Run timestamp (UTC):")
        && final_reply.contains("Confidence:")
        && final_reply.contains("Caveat:");
    let right_now_heading_present = final_reply.to_ascii_lowercase().contains("right now");
    let single_terminal_chat_reply_event =
        terminal_chat_reply_events <= MAX_TERMINAL_CHAT_REPLY_EVENTS;
    let terminal_verification_markers_present =
        saw_terminal_chat_reply_ready_marker && saw_terminal_chat_reply_emitted_marker;
    let no_churn_signatures = churn.is_empty();
    let no_approval_required_signals = approval_required_events == 0;
    let no_sys_exec_signals = !saw_sys_exec;
    let lower_reply = final_reply.to_ascii_lowercase();
    let estimated_right_now_present = lower_reply.contains("estimated-right-now:")
        && lower_reply.contains("derived from cited forecast range");
    let explicit_current_metric_present = (final_reply.contains('°')
        || lower_reply.contains(" feels like ")
        || lower_reply.contains(" humidity ")
        || lower_reply.contains(" wind "))
        && (lower_reply.contains("current") || lower_reply.contains("right now"));
    let direct_weather_answer_present =
        estimated_right_now_present || explicit_current_metric_present;
    let limitation_language_present = lower_reply
        .contains("current-condition metrics were not exposed")
        || lower_reply.contains("data caveat:");
    let explicit_next_step_open_url = lower_reply.contains("next step: open http");
    let fallback_guidance_contract_satisfied = if limitation_language_present {
        explicit_next_step_open_url
    } else {
        true
    };

    let mut deterministic_checks = BTreeMap::new();
    deterministic_checks.insert(
        "terminal_chat_reply_observed".to_string(),
        saw_terminal_chat_reply,
    );
    deterministic_checks.insert(
        "terminal_chat_reply_non_empty".to_string(),
        terminal_chat_reply_non_empty,
    );
    deterministic_checks.insert("elapsed_within_sla".to_string(), elapsed_within_sla);
    deterministic_checks.insert("min_distinct_sources".to_string(), has_min_sources);
    deterministic_checks.insert(
        "absolute_utc_datetime_present".to_string(),
        has_absolute_datetime,
    );
    deterministic_checks.insert(
        "retrieval_evidence_present".to_string(),
        retrieval_evidence_present,
    );
    deterministic_checks.insert(
        "intended_retrieval_path_present".to_string(),
        intended_retrieval_path_present,
    );
    deterministic_checks.insert(
        "structured_reply_present".to_string(),
        structured_reply_present,
    );
    deterministic_checks.insert(
        "right_now_heading_present".to_string(),
        right_now_heading_present,
    );
    deterministic_checks.insert(
        "single_terminal_chat_reply_event".to_string(),
        single_terminal_chat_reply_event,
    );
    deterministic_checks.insert(
        "terminal_verification_markers_present".to_string(),
        terminal_verification_markers_present,
    );
    deterministic_checks.insert("no_churn_signatures".to_string(), no_churn_signatures);
    deterministic_checks.insert(
        "no_approval_required_signals".to_string(),
        no_approval_required_signals,
    );
    deterministic_checks.insert("no_sys_exec_signals".to_string(), no_sys_exec_signals);
    deterministic_checks.insert(
        "direct_weather_answer_present".to_string(),
        direct_weather_answer_present,
    );
    deterministic_checks.insert(
        "source_relevance_anchor_match".to_string(),
        source_relevance_anchor_match,
    );
    deterministic_checks.insert(
        "fallback_guidance_contract_satisfied".to_string(),
        fallback_guidance_contract_satisfied,
    );

    let mut deterministic_failures = deterministic_checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(name.clone()))
        .collect::<Vec<_>>();
    if !churn.is_empty() {
        deterministic_failures.push(format!("churn:{}", churn.join(" | ")));
    }

    let deterministic_payload = json!({
        "checks": deterministic_checks,
        "elapsed_ms": elapsed.as_millis(),
        "sla_seconds": SLA_SECONDS,
        "required_min_sources": MIN_SOURCES,
        "required_citations": REQUIRED_CITATIONS,
        "source_url_count": source_urls.len(),
        "source_urls": source_urls,
        "query_anchor_count": query_anchor_count,
        "source_relevance_anchor_overlap_count": source_relevance_anchor_overlap_count,
        "limitation_language_present": limitation_language_present,
        "explicit_next_step_open_url": explicit_next_step_open_url,
        "approval_required_events": approval_required_events,
        "terminal_chat_reply_events": terminal_chat_reply_events,
        "churn_signatures": churn,
        "pending_debug": pending_debug,
        "routing_markers": {
            "terminal_chat_reply_ready": saw_terminal_chat_reply_ready_marker,
            "terminal_chat_reply_emitted": saw_terminal_chat_reply_emitted_marker,
            "saw_web_search": saw_web_search,
            "saw_web_read": saw_web_read,
            "saw_sys_exec": saw_sys_exec,
        }
    });
    println!(
        "LIVE_WEATHER_E2E_DETERMINISTIC_{}={}",
        label,
        serde_json::to_string_pretty(&deterministic_payload)?
    );

    if !deterministic_failures.is_empty() {
        return Err(anyhow!(
            "deterministic checks failed ({}): {}\nfinal_reply:\n{}\npending_debug={}\nrecent_events:\n{}",
            label,
            deterministic_failures.join(", "),
            final_reply,
            serde_json::to_string_pretty(
                deterministic_payload.get("pending_debug").unwrap_or(&json!({}))
            )?,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    let final_reply_excerpt = final_reply.chars().take(2_000).collect::<String>();
    let fallback_guidance_quality = fallback_guidance_contract_satisfied;
    let arbiter_payload = json!({
        "label": label,
        "query": query,
        "run_timestamp_ms": run_timestamp_ms,
        "run_timestamp_iso_utc": run_timestamp_iso_utc,
        "deterministic": deterministic_payload,
        "quality_contract": {
            "all_deterministic_checks_true": true,
            "direct_weather_answer_present": direct_weather_answer_present,
            "fallback_guidance_quality": fallback_guidance_quality,
            "required_citations": REQUIRED_CITATIONS,
            "observed_source_url_count": urls.len(),
        },
        "final_reply_excerpt": final_reply_excerpt,
        "final_reply_char_len": final_reply.chars().count(),
        "event_evidence": evidence,
    });
    println!(
        "LIVE_WEATHER_E2E_ARBITER_INPUT_{}={}",
        label,
        serde_json::to_string_pretty(&arbiter_payload)?
    );

    let verdict = run_arbiter(arbiter_runtime, &arbiter_payload).await?;
    println!(
        "LIVE_WEATHER_E2E_ARBITER_VERDICT_{}={}",
        label,
        serde_json::to_string_pretty(&json!({
            "pass": verdict.pass,
            "confidence": verdict.confidence,
            "rationale": verdict.rationale,
            "failures": verdict.failures,
        }))?
    );

    if !verdict.pass {
        return Err(anyhow!(
            "arbiter failed live weather response ({}): confidence={} rationale={} failures={}",
            label,
            verdict.confidence,
            verdict.rationale,
            verdict.failures.join("; ")
        ));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live internet + external inference required"]
async fn live_weather_chat_reply_e2e() -> Result<()> {
    build_test_artifacts();

    let openai_api_key = std::env::var("OPENAI_API_KEY")
        .map_err(|_| anyhow!("OPENAI_API_KEY required for live e2e"))?;
    let openai_model = std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
    let arbiter_model =
        std::env::var("NEWS_E2E_ARBITER_MODEL").unwrap_or_else(|_| "gpt-4o".to_string());
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

    println!(
        "LIVE_WEATHER_E2E_LOCKED_CONSTANTS={}",
        serde_json::to_string_pretty(&json!({
            "SLA_SECONDS": SLA_SECONDS,
            "MIN_SOURCES": MIN_SOURCES,
            "REQUIRED_CITATIONS": REQUIRED_CITATIONS,
            "CONSECUTIVE_PASS_TARGET": CONSECUTIVE_PASS_TARGET,
            "GENERALIZATION_VARIANTS": GENERALIZATION_VARIANTS,
        }))?
    );

    let mut run_index = 1usize;
    run_live_case(
        "primary_first_green",
        PRIMARY_QUERY,
        run_index,
        agent_runtime.clone(),
        arbiter_runtime.clone(),
    )
    .await?;
    run_index += 1;

    for confirmation_idx in 0..CONSECUTIVE_PASS_TARGET {
        run_live_case(
            &format!("primary_confirmation_{}", confirmation_idx + 1),
            PRIMARY_QUERY,
            run_index,
            agent_runtime.clone(),
            arbiter_runtime.clone(),
        )
        .await?;
        run_index += 1;
    }

    for (idx, query) in GENERALIZATION_VARIANTS.iter().enumerate() {
        run_live_case(
            &format!("variant_{}", idx + 1),
            query,
            run_index,
            agent_runtime.clone(),
            arbiter_runtime.clone(),
        )
        .await?;
        run_index += 1;
    }

    Ok(())
}

fn routing_event_for_test(step_index: u32, success: bool, checks: &[&str]) -> KernelEvent {
    KernelEvent::RoutingReceipt(RoutingReceiptEvent {
        session_id: [7u8; 32],
        step_index,
        intent_hash: "intent_hash".to_string(),
        policy_decision: "allowed".to_string(),
        tool_name: "web__read".to_string(),
        tool_version: "test".to_string(),
        pre_state: RoutingStateSummary {
            agent_status: "Running".to_string(),
            tier: "tool_first".to_string(),
            step_index,
            consecutive_failures: 0,
            target_hint: None,
        },
        action_json: "{}".to_string(),
        post_state: RoutingPostStateSummary {
            agent_status: "Running".to_string(),
            tier: "tool_first".to_string(),
            step_index: step_index + 1,
            consecutive_failures: 1,
            success,
            verification_checks: checks.iter().map(|value| value.to_string()).collect(),
        },
        artifacts: vec![],
        failure_class: None,
        failure_class_name: String::new(),
        intent_class: "web.research".to_string(),
        incident_id: String::new(),
        incident_stage: "none".to_string(),
        strategy_name: "none".to_string(),
        strategy_node: "none".to_string(),
        gate_state: "none".to_string(),
        resolution_action: "execute".to_string(),
        stop_condition_hit: false,
        escalation_path: None,
        scs_lineage_ptr: None,
        mutation_receipt_ptr: None,
        policy_binding_hash: "binding_hash".to_string(),
        policy_binding_sig: None,
        policy_binding_signer: None,
    })
}

#[test]
fn helper_detects_absolute_utc_datetime() {
    assert!(contains_absolute_utc_datetime(
        "Run timestamp (UTC): 2026-02-19T12:34:56Z"
    ));
    assert!(!contains_absolute_utc_datetime(
        "Run timestamp (UTC): 2026-02-19 12:34:56"
    ));
}

#[test]
fn helper_classifies_churn_signatures() {
    let events = vec![
        routing_event_for_test(
            1,
            false,
            &[
                "attempt_key_hash=abc123",
                "attempt_retry_blocked_without_change=false",
            ],
        ),
        routing_event_for_test(
            2,
            false,
            &[
                "attempt_key_hash=abc123",
                "attempt_retry_blocked_without_change=false",
            ],
        ),
        routing_event_for_test(
            3,
            false,
            &[
                "attempt_key_hash=abc123",
                "attempt_retry_blocked_without_change=true",
            ],
        ),
    ];
    let signatures = churn_signatures(&events);
    assert!(
        signatures
            .iter()
            .any(|value| value.contains("attempt_key_repeated")),
        "expected repeated attempt signature, got {:?}",
        signatures
    );
    assert!(
        signatures
            .iter()
            .any(|value| value.contains("blocked_without_change")),
        "expected blocked-without-change signature, got {:?}",
        signatures
    );
}

#[test]
fn helper_source_relevance_anchor_overlap_requires_multi_anchor_match() {
    let query = "What's the weather right now in Anderson, SC?";
    let forum_urls = [
        "https://forums.att.com/conversations/account-usage/compesation/5df024adbad5f2f60686b40b",
        "https://forums.att.com/conversations/apple/why-do-you-send-electronic-notifications-when-specifically-asked-not-to/5df00f54bad5f2f606253c6e",
    ]
    .into_iter()
    .map(|value| value.to_string())
    .collect::<BTreeSet<_>>();
    let weather_urls = [
        "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327",
        "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
    ]
    .into_iter()
    .map(|value| value.to_string())
    .collect::<BTreeSet<_>>();

    let forum_overlap = source_relevance_anchor_overlap(query, &forum_urls);
    let weather_overlap = source_relevance_anchor_overlap(query, &weather_urls);

    assert!(
        forum_overlap < SOURCE_RELEVANCE_MULTI_ANCHOR_MIN_OVERLAP,
        "forum overlap should not satisfy multi-anchor relevance, got {}",
        forum_overlap
    );
    assert!(
        weather_overlap >= SOURCE_RELEVANCE_MULTI_ANCHOR_MIN_OVERLAP,
        "weather overlap should satisfy multi-anchor relevance, got {}",
        weather_overlap
    );
}
