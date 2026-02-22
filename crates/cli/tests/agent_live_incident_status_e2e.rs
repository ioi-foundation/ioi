// Path: crates/cli/tests/agent_live_incident_status_e2e.rs
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
use std::path::{Path, PathBuf};
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

// Locked constants inferred from explicit query contract + existing reliability floor.
const SLA_SECONDS: u64 = 60;
const MIN_SOURCES: usize = 6;
const REQUIRED_STORIES: usize = 3;
const REQUIRED_CITATIONS_PER_STORY: usize = 2;
const CONSECUTIVE_PASS_TARGET: usize = 2;
const GENERALIZATION_VARIANTS: [&str; 3] = [
    "Give the top 3 currently active U.S.-impacting cloud or SaaS incidents from major status pages, include last-hour change, user impact, workaround, ETA confidence, and 2 citations each (UTC timestamps).",
    "As of current UTC time, summarize three active U.S.-relevant cloud platform incidents from official status dashboards: change in past hour, customer impact, workaround, ETA confidence, and two sources per incident.",
    "Right now in UTC, list the three most consequential ongoing cloud/SaaS incidents affecting U.S. users, with last-hour delta, impact, workaround, ETA confidence, and two citations each.",
];

const PRIMARY_QUERY: &str = "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents (major status pages), what changed in last hour, user impact, workaround, ETA confidence, 2 citations each.";
const MAX_TERMINAL_CHAT_REPLY_EVENTS: usize = 1;
const CHURN_REPEAT_THRESHOLD: usize = 3;
const QUERY_LITERAL_GATING_PATTERNS: [&str; 2] = [
    "top 3 active u.s.-impacting cloud/saas incidents",
    "what changed in last hour, user impact, workaround, eta confidence, 2 citations each",
];
const STATIC_AUDIT_FILES: [&str; 2] = [
    "crates/services/src/agentic/desktop/service/step/queue/support/mod.rs",
    "crates/services/src/agentic/desktop/service/step/queue/processing/mod.rs",
];
const ARBITER_ALLOWED_FAILURE_CODES: [&str; 5] = [
    "not_direct_or_actionable",
    "unsupported_claims",
    "workaround_or_eta_not_grounded",
    "insufficient_us_impact_specificity",
    "redundant_or_non_concise",
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

#[derive(Default, Debug, Clone)]
struct StorySection {
    title: String,
    has_what_happened: bool,
    has_changed_last_hour: bool,
    has_user_impact: bool,
    has_workaround: bool,
    has_eta_confidence: bool,
    citation_count: usize,
    citation_with_datetime_count: usize,
    unique_citation_urls: BTreeSet<String>,
    has_confidence: bool,
    has_caveat: bool,
}

fn parse_story_sections(reply: &str) -> Vec<StorySection> {
    let mut sections = Vec::new();
    let mut current: Option<StorySection> = None;
    let mut in_citations = false;

    for line in reply.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed
            .strip_prefix("Story ")
            .or_else(|| trimmed.strip_prefix("Incident "))
        {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            let title = rest
                .split_once(':')
                .map(|(_, rhs)| rhs.trim().to_string())
                .unwrap_or_default();
            current = Some(StorySection {
                title,
                ..Default::default()
            });
            in_citations = false;
            continue;
        }

        let Some(section) = current.as_mut() else {
            continue;
        };
        if trimmed.starts_with("What happened:") {
            section.has_what_happened = true;
            in_citations = false;
            continue;
        }
        if trimmed.starts_with("What changed in the last hour:") {
            section.has_changed_last_hour = true;
            in_citations = false;
            continue;
        }
        if trimmed.starts_with("User impact:") {
            section.has_user_impact = true;
            in_citations = false;
            continue;
        }
        if trimmed.starts_with("Workaround:") {
            section.has_workaround = true;
            in_citations = false;
            continue;
        }
        if trimmed.starts_with("ETA confidence:") {
            section.has_eta_confidence = true;
            in_citations = false;
            continue;
        }
        if trimmed == "Citations:" {
            in_citations = true;
            continue;
        }
        if in_citations && trimmed.starts_with("- ") {
            section.citation_count += 1;
            if contains_absolute_utc_datetime(trimmed) {
                section.citation_with_datetime_count += 1;
            }
            for url in extract_urls(trimmed) {
                section.unique_citation_urls.insert(url);
            }
            continue;
        }
        if trimmed.starts_with("Confidence:") {
            section.has_confidence = true;
            in_citations = false;
            continue;
        }
        if trimmed.starts_with("Caveat:") {
            section.has_caveat = true;
            in_citations = false;
        }
    }

    if let Some(section) = current {
        sections.push(section);
    }
    sections
}

fn validate_story_sections(reply: &str) -> Vec<String> {
    let sections = parse_story_sections(reply);
    let mut failures = Vec::new();
    if sections.len() != REQUIRED_STORIES {
        failures.push(format!(
            "required_story_count_mismatch expected={} got={}",
            REQUIRED_STORIES,
            sections.len()
        ));
        return failures;
    }

    for (idx, section) in sections.iter().enumerate() {
        let story_num = idx + 1;
        if section.title.trim().is_empty() {
            failures.push(format!("story_{}_missing_title", story_num));
        }
        if !section.has_what_happened {
            failures.push(format!("story_{}_missing_what_happened", story_num));
        }
        if !section.has_changed_last_hour {
            failures.push(format!("story_{}_missing_changed_last_hour", story_num));
        }
        if !section.has_user_impact {
            failures.push(format!("story_{}_missing_user_impact", story_num));
        }
        if !section.has_workaround {
            failures.push(format!("story_{}_missing_workaround", story_num));
        }
        if !section.has_eta_confidence {
            failures.push(format!("story_{}_missing_eta_confidence", story_num));
        }
        if section.citation_count < REQUIRED_CITATIONS_PER_STORY {
            failures.push(format!(
                "story_{}_citations_below_floor required>={} got={}",
                story_num, REQUIRED_CITATIONS_PER_STORY, section.citation_count
            ));
        }
        if section.citation_with_datetime_count < REQUIRED_CITATIONS_PER_STORY {
            failures.push(format!(
                "story_{}_citation_datetimes_below_floor required>={} got={}",
                story_num, REQUIRED_CITATIONS_PER_STORY, section.citation_with_datetime_count
            ));
        }
        if section.unique_citation_urls.len() < REQUIRED_CITATIONS_PER_STORY {
            failures.push(format!(
                "story_{}_distinct_citations_below_floor required>={} got={}",
                story_num,
                REQUIRED_CITATIONS_PER_STORY,
                section.unique_citation_urls.len()
            ));
        }
        if !section.has_confidence {
            failures.push(format!("story_{}_missing_confidence", story_num));
        }
        if !section.has_caveat {
            failures.push(format!("story_{}_missing_caveat", story_num));
        }
    }

    failures
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

fn is_iso_utc_at(bytes: &[u8], i: usize) -> bool {
    if i + 20 > bytes.len() {
        return false;
    }
    let s = &bytes[i..i + 20];
    s[0].is_ascii_digit()
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
        && s[19] == b'Z'
}

fn redact_iso_utc_timestamps(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if is_iso_utc_at(bytes, i) {
            out.push_str("<UTC_TIMESTAMP>");
            i += 20;
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(".."))
}

fn static_audit_no_query_literal_gating() -> bool {
    let repo_root = repo_root();
    let mut combined = String::new();

    for rel in STATIC_AUDIT_FILES {
        let path = repo_root.join(rel);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return false;
        };
        combined.push('\n');
        combined.push_str(&text.to_ascii_lowercase());
    }

    !QUERY_LITERAL_GATING_PATTERNS
        .iter()
        .any(|pattern| combined.contains(pattern))
}

async fn run_arbiter(
    runtime: Arc<dyn InferenceRuntime>,
    payload: &serde_json::Value,
) -> Result<ArbiterVerdict> {
    let prompt = format!(
        "You are a strict e2e arbiter for cloud/SaaS incident synthesis.\n\
Return JSON only with exact schema: \
{{\"pass\":bool,\"confidence\":\"high|medium|low\",\"rationale\":string,\"failures\":[string]}}.\n\
Decision policy (must follow exactly):\n\
1) Treat `deterministic_gate_passed=true` as authoritative (already validated separately).\n\
2) Judge only synthesis quality from `final_reply_excerpt` and metadata.\n\
3) Treat `run_timestamp_iso_utc` as the authoritative current UTC time baseline.\n\
4) Timestamps in `final_reply_excerpt` are intentionally redacted as <UTC_TIMESTAMP>; recency/time validity is already deterministic-validated.\n\
5) Set pass=false only if there is a clear synthesis-quality failure in clarity, grounding, or usefulness.\n\
6) If uncertain, prefer pass=true with confidence=medium or low.\n\
7) If pass=false, `failures` must be non-empty and every item must be one of: {:?}.\n\
8) If pass=true, `failures` must be [].\n\
Treat `run_timestamp_ms` and `run_timestamp_iso_utc` as authoritative for recency checks.\n\
Payload:\n{}",
        ARBITER_ALLOWED_FAILURE_CODES,
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
    if !matches!(verdict.confidence.as_str(), "high" | "medium" | "low") {
        return Err(anyhow!(
            "arbiter returned invalid confidence '{}'; expected high|medium|low",
            verdict.confidence
        ));
    }
    if verdict.pass && !verdict.failures.is_empty() {
        return Err(anyhow!(
            "arbiter returned pass=true but non-empty failures: {:?}",
            verdict.failures
        ));
    }
    if !verdict.pass && verdict.failures.is_empty() {
        return Err(anyhow!(
            "arbiter returned pass=false but empty failures; rationale={}",
            verdict.rationale
        ));
    }
    for failure in &verdict.failures {
        if !ARBITER_ALLOWED_FAILURE_CODES
            .iter()
            .any(|allowed| allowed == failure)
        {
            return Err(anyhow!(
                "arbiter returned unsupported failure code '{}'; allowed={:?}",
                failure,
                ARBITER_ALLOWED_FAILURE_CODES
            ));
        }
    }
    Ok(verdict)
}

fn session_id_for_index(index: usize) -> [u8; 32] {
    let mut session_id = [0u8; 32];
    for (offset, byte) in session_id.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_add(0x42).wrapping_add(offset as u8);
    }
    session_id
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
    let (scs, _scs_tmp_dir) = build_scs(&format!("live_incident_{}.scs", run_index))?;
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
            "live incident e2e exceeded SLA: elapsed={}ms final_status={:?}\nrecent_events:\n{}",
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
    let mut terminal_chat_reply_events = 0usize;
    let mut final_reply = String::new();
    let mut saw_web_routing = false;
    let mut saw_web_retrieve_receipt = false;
    let mut saw_web_search_routing = false;
    let mut saw_web_read_routing = false;
    let mut saw_web_search_receipt = false;
    let mut saw_web_read_receipt = false;
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
            }
            KernelEvent::WorkloadReceipt(workload) => {
                if let WorkloadReceipt::WebRetrieve(web) = &workload.receipt {
                    if matches!(web.tool_name.as_str(), "web__search" | "web__read") {
                        saw_web_retrieve_receipt = true;
                        if web.tool_name == "web__search" {
                            saw_web_search_receipt = true;
                        }
                        if web.tool_name == "web__read" {
                            saw_web_read_receipt = true;
                        }
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
                    if receipt.tool_name == "web__search" {
                        saw_web_search_routing = true;
                    }
                    if receipt.tool_name == "web__read" {
                        saw_web_read_routing = true;
                    }
                    evidence.push(format!(
                        "routing:{} decision={} success={}",
                        receipt.tool_name, receipt.policy_decision, receipt.post_state.success
                    ));
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
            _ => {}
        }
    }

    let urls = extract_urls(&final_reply);
    let source_urls = urls.iter().cloned().collect::<Vec<_>>();
    let story_sections = parse_story_sections(&final_reply);
    let story_section_failures = validate_story_sections(&final_reply);
    let churn = churn_signatures(&captured_events);
    let static_audit_passed = static_audit_no_query_literal_gating();

    let terminal_chat_reply_non_empty = !final_reply.trim().is_empty();
    let elapsed_within_sla = elapsed <= deadline;
    let has_min_sources = urls.len() >= MIN_SOURCES;
    let has_absolute_datetime = contains_absolute_utc_datetime(&final_reply);
    let has_retrieval_evidence = saw_web_routing || saw_web_retrieve_receipt;
    let intended_retrieval_path_present = (saw_web_search_routing || saw_web_search_receipt)
        && (saw_web_read_routing || saw_web_read_receipt);
    let strict_story_contract_passed = story_section_failures.is_empty();
    let single_terminal_chat_reply_event =
        terminal_chat_reply_events <= MAX_TERMINAL_CHAT_REPLY_EVENTS;
    let terminal_verification_markers_present =
        saw_terminal_chat_reply_ready_marker && saw_terminal_chat_reply_emitted_marker;
    let no_churn_signatures = churn.is_empty();

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
        "strict_story_contract_passed".to_string(),
        strict_story_contract_passed,
    );
    deterministic_checks.insert(
        "single_terminal_chat_reply_event".to_string(),
        single_terminal_chat_reply_event,
    );
    deterministic_checks.insert(
        "retrieval_evidence_present".to_string(),
        has_retrieval_evidence,
    );
    deterministic_checks.insert(
        "intended_retrieval_path_present".to_string(),
        intended_retrieval_path_present,
    );
    deterministic_checks.insert(
        "terminal_verification_markers_present".to_string(),
        terminal_verification_markers_present,
    );
    deterministic_checks.insert("no_churn_signatures".to_string(), no_churn_signatures);
    deterministic_checks.insert(
        "static_audit_no_query_literal_gating".to_string(),
        static_audit_passed,
    );

    let mut deterministic_failures = deterministic_checks
        .iter()
        .filter_map(|(name, passed)| (!*passed).then_some(name.clone()))
        .collect::<Vec<_>>();
    if !story_section_failures.is_empty() {
        deterministic_failures.extend(
            story_section_failures
                .iter()
                .map(|failure| format!("story_contract:{}", failure)),
        );
    }
    if !churn.is_empty() {
        deterministic_failures.push(format!("churn:{}", churn.join(" | ")));
    }

    let deterministic_payload = json!({
        "checks": deterministic_checks,
        "elapsed_ms": elapsed.as_millis(),
        "sla_seconds": SLA_SECONDS,
        "required_stories": REQUIRED_STORIES,
        "required_citations_per_story": REQUIRED_CITATIONS_PER_STORY,
        "required_min_sources": MIN_SOURCES,
        "consecutive_pass_target": CONSECUTIVE_PASS_TARGET,
        "generalization_variant_count": GENERALIZATION_VARIANTS.len(),
        "source_url_count": source_urls.len(),
        "terminal_chat_reply_events": terminal_chat_reply_events,
        "source_urls": source_urls,
        "story_section_summary": story_sections
            .iter()
            .enumerate()
            .map(|(idx, story)| json!({
                "story_index": idx + 1,
                "title": story.title.clone(),
                "citation_count": story.citation_count,
                "citation_with_datetime_count": story.citation_with_datetime_count,
                "distinct_citation_url_count": story.unique_citation_urls.len(),
                "has_what_happened": story.has_what_happened,
                "has_changed_last_hour": story.has_changed_last_hour,
                "has_user_impact": story.has_user_impact,
                "has_workaround": story.has_workaround,
                "has_eta_confidence": story.has_eta_confidence,
                "has_confidence": story.has_confidence,
                "has_caveat": story.has_caveat,
            }))
            .collect::<Vec<_>>(),
        "story_section_failures": story_section_failures,
        "churn_signatures": churn,
        "routing_markers": {
            "terminal_chat_reply_ready": saw_terminal_chat_reply_ready_marker,
            "terminal_chat_reply_emitted": saw_terminal_chat_reply_emitted_marker,
            "saw_web_search": saw_web_search_routing || saw_web_search_receipt,
            "saw_web_read": saw_web_read_routing || saw_web_read_receipt,
        }
    });

    println!(
        "LIVE_INCIDENT_E2E_DETERMINISTIC_{}={}",
        label,
        serde_json::to_string_pretty(&deterministic_payload)?
    );

    if !deterministic_failures.is_empty() {
        return Err(anyhow!(
            "deterministic checks failed ({}): {}\nfinal_reply:\n{}\nrecent_events:\n{}",
            label,
            deterministic_failures.join(", "),
            final_reply,
            summarize_recent_events(&captured_events, 24)
        ));
    }

    let final_reply_excerpt = final_reply.chars().take(2_000).collect::<String>();
    let final_reply_excerpt = redact_iso_utc_timestamps(&final_reply_excerpt);
    let arbiter_payload = json!({
        "label": label,
        "query": query,
        "run_timestamp_ms": run_timestamp_ms,
        "run_timestamp_iso_utc": run_timestamp_iso_utc,
        "deterministic_gate_passed": true,
        "deterministic_time_validity_passed": true,
        "deterministic": deterministic_payload,
        "final_reply_excerpt": final_reply_excerpt,
        "final_reply_char_len": final_reply.chars().count(),
        "source_url_count": urls.len(),
        "event_evidence": evidence,
    });
    println!(
        "LIVE_INCIDENT_E2E_ARBITER_INPUT_{}={}",
        label,
        serde_json::to_string_pretty(&arbiter_payload)?
    );

    let verdict = run_arbiter(arbiter_runtime, &arbiter_payload).await?;
    println!(
        "LIVE_INCIDENT_E2E_ARBITER_VERDICT_{}={}",
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
            "arbiter failed live incident response ({}): confidence={} rationale={} failures={}",
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
async fn live_cloud_saas_incident_chat_reply_e2e() -> Result<()> {
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
        "LIVE_INCIDENT_E2E_LOCKED_CONSTANTS={}",
        serde_json::to_string_pretty(&json!({
            "SLA_SECONDS": SLA_SECONDS,
            "MIN_SOURCES": MIN_SOURCES,
            "REQUIRED_STORIES": REQUIRED_STORIES,
            "REQUIRED_CITATIONS_PER_STORY": REQUIRED_CITATIONS_PER_STORY,
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
fn helper_parses_incident_sections_strictly() {
    let reply = "\
Story 1: A\n\
What happened: A1\n\
What changed in the last hour: A2\n\
User impact: A3\n\
Workaround: A4\n\
ETA confidence: medium\n\
Citations:\n\
- Src A | https://a.example.com | 2026-02-19T12:00:00Z | retrieved_utc\n\
- Src B | https://b.example.com | 2026-02-19T12:01:00Z | retrieved_utc\n\
Confidence: high\n\
Caveat: C1\n\
\n\
Story 2: B\n\
What happened: B1\n\
What changed in the last hour: B2\n\
User impact: B3\n\
Workaround: B4\n\
ETA confidence: low\n\
Citations:\n\
- Src C | https://c.example.com | 2026-02-19T12:02:00Z | retrieved_utc\n\
- Src D | https://d.example.com | 2026-02-19T12:03:00Z | retrieved_utc\n\
Confidence: medium\n\
Caveat: C2\n\
\n\
Story 3: C\n\
What happened: C1\n\
What changed in the last hour: C2\n\
User impact: C3\n\
Workaround: C4\n\
ETA confidence: high\n\
Citations:\n\
- Src E | https://e.example.com | 2026-02-19T12:04:00Z | retrieved_utc\n\
- Src F | https://f.example.com | 2026-02-19T12:05:00Z | retrieved_utc\n\
Confidence: low\n\
Caveat: C3\n";

    let sections = parse_story_sections(reply);
    assert_eq!(sections.len(), REQUIRED_STORIES);
    assert!(validate_story_sections(reply).is_empty());
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
