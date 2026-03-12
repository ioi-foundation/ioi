use ioi_types::app::agentic::IntentScopeProfile;
use ioi_types::app::agentic::{WebRetrievalAffordance, WebRetrievalContract};
use serde::Serialize;

use super::judge::ArbiterVerdict;

pub type LocalSniffFn = fn(&RunObservation) -> LocalJudgeResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionProfile {
    Hermetic,
    PolicyGate,
    Privileged,
}

#[derive(Clone)]
pub struct QueryCase {
    pub id: &'static str,
    pub query: &'static str,
    pub success_definition: &'static str,
    pub seeded_intent_id: &'static str,
    pub intent_scope: IntentScopeProfile,
    pub seed_resolved_intent: bool,
    pub expected_pass: bool,
    pub execution_profile: ExecutionProfile,
    pub sla_seconds: u64,
    pub max_steps: u32,
    pub min_local_score: f64,
    pub allow_retry_blocked_completion_with_local_evidence: bool,
    pub allow_timeout_completion_with_local_evidence: bool,
    pub local_sniff: LocalSniffFn,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionEvidence {
    pub tool_name: String,
    pub agent_status: String,
    pub output_excerpt: String,
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedToolCallEvidence {
    pub step_index: u32,
    pub tool_name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommandHistoryEvidence {
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CecReceiptEvidence {
    pub contract_version: String,
    pub stage: String,
    pub key: String,
    pub satisfied: bool,
    pub timestamp_ms: u64,
    pub probe_source: Option<String>,
    pub observed_value: Option<String>,
    pub evidence_type: Option<String>,
    pub provider_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntentResolutionEvidence {
    pub intent_id: String,
    pub selected_intent_id: String,
    pub scope: String,
    pub band: String,
    pub score: f32,
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct EnvironmentReceiptObservation {
    pub key: String,
    #[serde(default)]
    pub observed_values: Vec<String>,
    pub probe_source: Option<String>,
    pub timestamp_ms: Option<u64>,
    pub satisfied: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationFact {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct WebObservation {
    pub retrieval_contract: Option<WebRetrievalContract>,
    pub query_contract: Option<String>,
    pub query_value: Option<String>,
    pub currentness_required: Option<bool>,
    pub runtime_locality_required: Option<bool>,
    pub runtime_locality_scope: Option<String>,
    pub runtime_locality_alignment: Option<bool>,
    pub semantic_subject_alignment_required: Option<bool>,
    pub semantic_subject_alignment_floor_met: Option<bool>,
    pub semantic_subject_alignment_urls: Vec<String>,
    pub min_sources: Option<usize>,
    pub sources_success: Option<usize>,
    pub source_floor_met: Option<bool>,
    pub selected_source_quality_floor_met: Option<bool>,
    pub selected_source_subject_alignment_floor_met: Option<bool>,
    pub selected_source_count: Option<usize>,
    pub selected_source_distinct_domains: Option<usize>,
    pub selected_source_urls: Vec<String>,
    pub selected_source_subject_alignment_urls: Vec<String>,
    pub local_business_entity_floor_met: Option<bool>,
    pub local_business_entity_anchor_floor_met: Option<bool>,
    pub local_business_entity_names: Vec<String>,
    pub local_business_entity_source_urls: Vec<String>,
    pub local_business_entity_anchor_source_urls: Vec<String>,
    pub local_business_entity_anchor_mismatched_urls: Vec<String>,
    pub local_business_menu_inventory_floor_met: Option<bool>,
    pub local_business_menu_inventory_total_item_count: Option<usize>,
    pub local_business_menu_inventory_source_urls: Vec<String>,
    pub story_slots_observed: Option<usize>,
    pub story_slot_floor_met: Option<bool>,
    pub story_citation_floor_met: Option<bool>,
    pub comparison_ready: Option<bool>,
    pub single_snapshot_metric_grounding: Option<bool>,
    pub provider_candidates: Vec<WebProviderCandidateObservation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebProviderCandidateObservation {
    pub provider_id: String,
    pub modality: Option<String>,
    pub source_count: usize,
    pub selected: bool,
    pub success: bool,
    pub execution_attempted: Option<bool>,
    pub execution_satisfied: Option<bool>,
    pub execution_failure_reason: Option<String>,
    pub request_url: Option<String>,
    pub challenge_reason: Option<String>,
    pub affordances: Vec<WebRetrievalAffordance>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScreenshotObservation {
    pub capture_action_count: usize,
    pub capture_failure_count: usize,
    pub gui_snapshot_action_count: usize,
    pub gui_snapshot_routing_count: usize,
    pub capture_route_seen: bool,
    pub capture_route_terminalized: bool,
    pub incident_resolved: bool,
    pub approval_gate_seen: bool,
    pub approval_transition_seen: bool,
    pub no_gui_snapshot_fallback: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MailReadLatestPayloadObservation {
    pub operation: Option<String>,
    pub mailbox: Option<String>,
    pub citation: Option<String>,
    pub message_id: Option<String>,
    pub from: Option<String>,
    pub subject: Option<String>,
    pub preview: Option<String>,
    pub received_at_ms: Option<u64>,
    pub received_at_utc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MailReplyPayloadObservation {
    pub operation: Option<String>,
    pub mailbox: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub sent_message_id: Option<String>,
    pub citation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MailObservation {
    pub read_latest_success_count: usize,
    pub read_latest_failure_count: usize,
    pub reply_success_count: usize,
    pub reply_failure_count: usize,
    pub read_latest_payloads: Vec<MailReadLatestPayloadObservation>,
    pub reply_payloads: Vec<MailReplyPayloadObservation>,
    pub connector_path_required: bool,
    pub non_connector_tool_blocked: bool,
    pub invalid_tool_call_fail_fast: bool,
    pub system_fail_degraded_to_reply: bool,
    pub fallback_marker_present: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GoogleGmailPayloadObservation {
    pub action_id: Option<String>,
    pub message_id: Option<String>,
    pub thread_id: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub body_text: Option<String>,
    pub label_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GoogleCalendarPayloadObservation {
    pub action_id: Option<String>,
    pub event_id: Option<String>,
    pub calendar_id: Option<String>,
    pub summary: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub html_link: Option<String>,
    pub attendee_emails: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct GoogleObservation {
    pub gmail_draft_success_count: usize,
    pub gmail_draft_failure_count: usize,
    pub gmail_send_success_count: usize,
    pub gmail_send_failure_count: usize,
    pub calendar_create_success_count: usize,
    pub calendar_create_failure_count: usize,
    pub gmail_draft_payloads: Vec<GoogleGmailPayloadObservation>,
    pub gmail_send_payloads: Vec<GoogleGmailPayloadObservation>,
    pub calendar_create_payloads: Vec<GoogleCalendarPayloadObservation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunObservation {
    pub case_id: String,
    pub query: String,
    pub run_timestamp_ms: u64,
    pub run_timestamp_iso_utc: String,
    pub elapsed_ms: u128,
    pub completed: bool,
    pub failed: bool,
    pub final_status: String,
    pub terminal_pause_reason: Option<String>,
    pub terminal_failure_reason: Option<String>,
    pub final_reply: String,
    pub chat_reply_count: usize,
    pub action_tools: Vec<String>,
    pub planned_tool_calls: Vec<PlannedToolCallEvidence>,
    pub routing_tools: Vec<String>,
    pub workload_tools: Vec<String>,
    pub routing_policy_decisions: Vec<String>,
    pub routing_failure_classes: Vec<String>,
    pub routing_stop_condition_hits: usize,
    pub verification_checks: Vec<String>,
    pub verification_facts: Vec<VerificationFact>,
    pub approval_required_events: usize,
    pub action_evidence: Vec<ActionEvidence>,
    pub action_error_classes: Vec<String>,
    pub command_history_evidence: Vec<CommandHistoryEvidence>,
    pub cec_receipts: Vec<CecReceiptEvidence>,
    pub intent_resolution_evidence: Vec<IntentResolutionEvidence>,
    pub environment_receipts: Vec<EnvironmentReceiptObservation>,
    pub web: Option<WebObservation>,
    pub screenshot: Option<ScreenshotObservation>,
    pub mail: Option<MailObservation>,
    pub google: Option<GoogleObservation>,
    pub event_excerpt: Vec<String>,
    pub kernel_event_count: usize,
    pub kernel_log_lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

impl LocalCheck {
    pub fn new(name: &'static str, passed: bool, detail: impl Into<String>) -> Self {
        Self {
            name,
            passed,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalJudgeResult {
    pub pass: bool,
    pub score: f64,
    pub checks: Vec<LocalCheck>,
    pub failures: Vec<String>,
}

impl LocalJudgeResult {
    pub fn from_checks(checks: Vec<LocalCheck>) -> Self {
        let passed_count = checks.iter().filter(|check| check.passed).count();
        let total = checks.len();
        let score = if total == 0 {
            0.0
        } else {
            passed_count as f64 / total as f64
        };
        let failures = checks
            .iter()
            .filter(|check| !check.passed)
            .map(|check| check.name.to_string())
            .collect::<Vec<_>>();

        Self {
            pass: total > 0 && failures.is_empty(),
            score,
            checks,
            failures,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseOutcome {
    pub case_id: String,
    pub query: String,
    pub expected_pass: bool,
    pub observed_pass: bool,
    pub completed: bool,
    pub final_status: String,
    pub local: LocalJudgeResult,
    pub arbiter: ArbiterVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolNamespace {
    Browser,
    Computer,
    Filesystem,
    Gui,
    Mail,
    Math,
    Memory,
    Net,
    Os,
    Sys,
    Time,
    Web,
}

pub fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

pub fn tool_namespace(tool_name: &str) -> Option<ToolNamespace> {
    let normalized = tool_name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if normalized == "computer" {
        return Some(ToolNamespace::Computer);
    }
    if normalized == "time" || normalized.starts_with("time__") {
        return Some(ToolNamespace::Time);
    }
    if normalized.starts_with("wallet_network__mail_")
        || normalized.starts_with("wallet_mail_")
        || normalized.starts_with("mail__")
    {
        return Some(ToolNamespace::Mail);
    }
    if normalized.starts_with("browser__") {
        return Some(ToolNamespace::Browser);
    }
    if normalized.starts_with("filesystem__") {
        return Some(ToolNamespace::Filesystem);
    }
    if normalized.starts_with("gui__") {
        return Some(ToolNamespace::Gui);
    }
    if normalized.starts_with("math__") {
        return Some(ToolNamespace::Math);
    }
    if normalized.starts_with("memory__") {
        return Some(ToolNamespace::Memory);
    }
    if normalized.starts_with("net__") {
        return Some(ToolNamespace::Net);
    }
    if normalized.starts_with("os__") {
        return Some(ToolNamespace::Os);
    }
    if normalized.starts_with("sys__") {
        return Some(ToolNamespace::Sys);
    }
    if normalized.starts_with("web__") {
        return Some(ToolNamespace::Web);
    }
    None
}

pub fn has_tool_name(tools: &[String], expected: &str) -> bool {
    tools
        .iter()
        .any(|tool| tool.trim().eq_ignore_ascii_case(expected.trim()))
}

pub fn has_any_tool_name(tools: &[String], expected: &[&str]) -> bool {
    expected
        .iter()
        .any(|tool_name| has_tool_name(tools, tool_name))
}

pub fn has_all_tool_names(tools: &[String], expected: &[&str]) -> bool {
    expected
        .iter()
        .all(|tool_name| has_tool_name(tools, tool_name))
}

pub fn has_tool_namespace(tools: &[String], expected: ToolNamespace) -> bool {
    tools
        .iter()
        .filter_map(|tool| tool_namespace(tool))
        .any(|namespace| namespace == expected)
}

pub fn observation_has_tool_name(observation: &RunObservation, expected: &str) -> bool {
    has_tool_name(&observation.action_tools, expected)
        || has_tool_name(&observation.routing_tools, expected)
        || has_tool_name(&observation.workload_tools, expected)
}

pub fn observation_has_any_tool_name(observation: &RunObservation, expected: &[&str]) -> bool {
    has_any_tool_name(&observation.action_tools, expected)
        || has_any_tool_name(&observation.routing_tools, expected)
        || has_any_tool_name(&observation.workload_tools, expected)
}

pub fn observation_has_all_tool_names(observation: &RunObservation, expected: &[&str]) -> bool {
    expected
        .iter()
        .all(|tool_name| observation_has_tool_name(observation, tool_name))
}

pub fn observation_has_tool_namespace(
    observation: &RunObservation,
    expected: ToolNamespace,
) -> bool {
    has_tool_namespace(&observation.action_tools, expected)
        || has_tool_namespace(&observation.routing_tools, expected)
        || has_tool_namespace(&observation.workload_tools, expected)
}

pub fn has_tool_with_token(tools: &[String], token: &str) -> bool {
    let normalized = token.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }

    match normalized.as_str() {
        "computer" => has_tool_name(tools, "computer"),
        "browser__" => has_tool_namespace(tools, ToolNamespace::Browser),
        "filesystem__" => has_tool_namespace(tools, ToolNamespace::Filesystem),
        "gui__" => has_tool_namespace(tools, ToolNamespace::Gui),
        "math__" => has_tool_namespace(tools, ToolNamespace::Math),
        "memory__" => has_tool_namespace(tools, ToolNamespace::Memory),
        "net__" => has_tool_namespace(tools, ToolNamespace::Net),
        "os__" => has_tool_namespace(tools, ToolNamespace::Os),
        "sys__" => has_tool_namespace(tools, ToolNamespace::Sys),
        "time__" => has_tool_namespace(tools, ToolNamespace::Time),
        "web__" => has_tool_namespace(tools, ToolNamespace::Web),
        "mail_read_latest" => has_any_tool_name(
            tools,
            &[
                "wallet_network__mail_read_latest",
                "wallet_mail_read_latest",
                "mail__read_latest",
            ],
        ),
        "mail_list_recent" => has_any_tool_name(
            tools,
            &[
                "wallet_network__mail_list_recent",
                "wallet_mail_list_recent",
                "mail__list_recent",
            ],
        ),
        "mail_delete_spam" => has_any_tool_name(
            tools,
            &[
                "wallet_network__mail_delete_spam",
                "wallet_mail_delete_spam",
                "mail__delete_spam",
            ],
        ),
        "mail_reply" => has_any_tool_name(
            tools,
            &[
                "wallet_network__mail_reply",
                "wallet_mail_reply",
                "mail__reply",
            ],
        ),
        _ => has_tool_name(tools, &normalized),
    }
}

pub fn truncate_chars(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        compact
    } else {
        compact.chars().take(max_chars).collect::<String>() + "..."
    }
}

pub fn uri_scheme(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let scheme = trimmed.split_once(':')?.0.trim();
    if scheme.is_empty() {
        return None;
    }

    let mut chars = scheme.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.')) {
        Some(scheme.to_ascii_lowercase())
    } else {
        None
    }
}

pub fn has_cec_receipt(
    observation: &RunObservation,
    stage: &str,
    key: &str,
    satisfied: Option<bool>,
) -> bool {
    observation.cec_receipts.iter().any(|receipt| {
        receipt.stage.eq_ignore_ascii_case(stage)
            && receipt.key.eq_ignore_ascii_case(key)
            && satisfied
                .map(|expected| receipt.satisfied == expected)
                .unwrap_or(true)
    })
}

pub fn has_cec_stage(observation: &RunObservation, stage: &str, satisfied: Option<bool>) -> bool {
    observation.cec_receipts.iter().any(|receipt| {
        receipt.stage.eq_ignore_ascii_case(stage)
            && satisfied
                .map(|expected| receipt.satisfied == expected)
                .unwrap_or(true)
    })
}

fn latest_cec_receipt<'a>(
    observation: &'a RunObservation,
    stage: &str,
    key: &str,
) -> Option<&'a CecReceiptEvidence> {
    observation.cec_receipts.iter().rev().find(|receipt| {
        receipt.stage.eq_ignore_ascii_case(stage) && receipt.key.eq_ignore_ascii_case(key)
    })
}

pub fn cec_receipt_value(observation: &RunObservation, stage: &str, key: &str) -> Option<String> {
    latest_cec_receipt(observation, stage, key).and_then(|receipt| receipt.observed_value.clone())
}

pub fn cec_receipt_satisfied(observation: &RunObservation, stage: &str, key: &str) -> Option<bool> {
    latest_cec_receipt(observation, stage, key).map(|receipt| receipt.satisfied)
}

pub fn cec_receipt_values(observation: &RunObservation, stage: &str, key: &str) -> Vec<String> {
    observation
        .cec_receipts
        .iter()
        .filter(|receipt| {
            receipt.stage.eq_ignore_ascii_case(stage) && receipt.key.eq_ignore_ascii_case(key)
        })
        .filter_map(|receipt| receipt.observed_value.clone())
        .collect()
}

pub fn cec_receipt_latest_values(
    observation: &RunObservation,
    stage: &str,
    key: &str,
) -> Vec<String> {
    let Some(last_idx) = observation.cec_receipts.iter().rposition(|receipt| {
        receipt.stage.eq_ignore_ascii_case(stage) && receipt.key.eq_ignore_ascii_case(key)
    }) else {
        return Vec::new();
    };

    let latest_timestamp = observation.cec_receipts[last_idx].timestamp_ms;
    let mut first_idx = last_idx;
    let mut crossed_interleaved_receipt = false;
    while first_idx > 0 {
        let prev = &observation.cec_receipts[first_idx - 1];
        let matches_key =
            prev.stage.eq_ignore_ascii_case(stage) && prev.key.eq_ignore_ascii_case(key);
        if matches_key {
            if crossed_interleaved_receipt && prev.timestamp_ms != latest_timestamp {
                break;
            }
            first_idx -= 1;
            continue;
        }
        if prev.timestamp_ms != latest_timestamp {
            break;
        }
        crossed_interleaved_receipt = true;
        first_idx -= 1;
    }

    observation
        .cec_receipts
        .iter()
        .skip(first_idx)
        .take(last_idx - first_idx + 1)
        .filter(|receipt| {
            receipt.stage.eq_ignore_ascii_case(stage) && receipt.key.eq_ignore_ascii_case(key)
        })
        .filter_map(|receipt| receipt.observed_value.clone())
        .collect()
}

pub fn cec_receipt_bool(observation: &RunObservation, stage: &str, key: &str) -> Option<bool> {
    cec_receipt_value(observation, stage, key).and_then(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        }
    })
}

pub fn cec_receipt_usize(observation: &RunObservation, stage: &str, key: &str) -> Option<usize> {
    cec_receipt_value(observation, stage, key).and_then(|value| value.trim().parse::<usize>().ok())
}

pub fn parse_verification_fact(raw: &str) -> VerificationFact {
    let trimmed = raw.trim();
    if let Some((left, right)) = trimmed.split_once('=') {
        VerificationFact {
            key: left.trim().to_string(),
            value: Some(right.trim().to_string()),
        }
    } else {
        VerificationFact {
            key: trimmed.to_string(),
            value: None,
        }
    }
}

pub fn parse_verification_facts(checks: &[String]) -> Vec<VerificationFact> {
    checks
        .iter()
        .map(|check| parse_verification_fact(check))
        .collect()
}

fn normalize_environment_receipt_key(key: &str) -> Option<&str> {
    key.trim().strip_prefix("env_receipt::")
}

fn is_environment_receipt_query(key: &str) -> bool {
    normalize_environment_receipt_key(key).is_some()
}

fn environment_receipt_value_from_projection(
    receipt: &EnvironmentReceiptObservation,
    normalized_key: &str,
) -> Option<String> {
    if receipt.key.eq_ignore_ascii_case(normalized_key) {
        return receipt.observed_values.last().cloned();
    }

    normalized_key
        .strip_suffix("_probe_source")
        .filter(|base| receipt.key.eq_ignore_ascii_case(base))
        .and_then(|_| receipt.probe_source.clone())
        .or_else(|| {
            normalized_key
                .strip_suffix("_timestamp_ms")
                .filter(|base| receipt.key.eq_ignore_ascii_case(base))
                .and_then(|_| receipt.timestamp_ms.map(|value| value.to_string()))
        })
        .or_else(|| {
            normalized_key
                .strip_suffix("_satisfied")
                .filter(|base| receipt.key.eq_ignore_ascii_case(base))
                .and_then(|_| receipt.satisfied.map(|value| value.to_string()))
        })
}

pub fn environment_value(observation: &RunObservation, key: &str) -> Option<String> {
    let normalized_key = normalize_environment_receipt_key(key)?;
    observation
        .environment_receipts
        .iter()
        .rev()
        .find_map(|receipt| environment_receipt_value_from_projection(receipt, normalized_key))
}

pub fn environment_values(observation: &RunObservation, key: &str) -> Vec<String> {
    let Some(normalized_key) = normalize_environment_receipt_key(key) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    for receipt in &observation.environment_receipts {
        if receipt.key.eq_ignore_ascii_case(normalized_key) {
            values.extend(receipt.observed_values.iter().cloned());
            continue;
        }
        if let Some(value) = environment_receipt_value_from_projection(receipt, normalized_key) {
            values.push(value);
        }
    }
    values
}

pub fn environment_bool(observation: &RunObservation, key: &str) -> Option<bool> {
    environment_value(observation, key).and_then(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        }
    })
}

pub fn environment_u64(observation: &RunObservation, key: &str) -> Option<u64> {
    environment_value(observation, key).and_then(|value| value.trim().parse::<u64>().ok())
}

pub fn has_verification_pair(observation: &RunObservation, key: &str, value: &str) -> bool {
    if let Some(actual) = environment_value(observation, key) {
        return actual.eq_ignore_ascii_case(value);
    }
    if is_environment_receipt_query(key) {
        return false;
    }
    observation.verification_facts.iter().any(|fact| {
        fact.key.eq_ignore_ascii_case(key)
            && fact
                .value
                .as_ref()
                .map(|actual| actual.eq_ignore_ascii_case(value))
                .unwrap_or(false)
    })
}

pub fn verification_value(observation: &RunObservation, key: &str) -> Option<String> {
    if let Some(value) = environment_value(observation, key) {
        return Some(value);
    }
    if is_environment_receipt_query(key) {
        return None;
    }
    observation
        .verification_facts
        .iter()
        .find(|fact| fact.key.eq_ignore_ascii_case(key))
        .and_then(|fact| fact.value.clone())
}

pub fn verification_values(observation: &RunObservation, key: &str) -> Vec<String> {
    let environment_values = environment_values(observation, key);
    if !environment_values.is_empty() {
        return environment_values;
    }
    if is_environment_receipt_query(key) {
        return Vec::new();
    }
    observation
        .verification_facts
        .iter()
        .filter(|fact| fact.key.eq_ignore_ascii_case(key))
        .filter_map(|fact| fact.value.clone())
        .collect()
}

pub fn verification_bool(observation: &RunObservation, key: &str) -> Option<bool> {
    if let Some(value) = environment_bool(observation, key) {
        return Some(value);
    }
    verification_value(observation, key).and_then(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        }
    })
}

pub fn verification_u64(observation: &RunObservation, key: &str) -> Option<u64> {
    if let Some(value) = environment_u64(observation, key) {
        return Some(value);
    }
    verification_value(observation, key).and_then(|value| value.trim().parse::<u64>().ok())
}

pub fn has_policy_decision(observation: &RunObservation, decision: &str) -> bool {
    observation
        .routing_policy_decisions
        .iter()
        .any(|value| value.eq_ignore_ascii_case(decision))
        || has_verification_pair(observation, "policy_decision", decision)
}

pub fn has_unresolved_approval_gate(observation: &RunObservation) -> bool {
    if observation.approval_required_events == 0 {
        return false;
    }

    let approved = has_policy_decision(observation, "approved");
    let denied = has_policy_decision(observation, "denied");
    let requires_approval = has_policy_decision(observation, "require_approval");
    let awaiting_sudo = verification_bool(observation, "awaiting_sudo_password").unwrap_or(false);
    let awaiting_clarification =
        verification_bool(observation, "awaiting_clarification").unwrap_or(false);
    let approval_pending_cleared =
        verification_bool(observation, "approval_pending_cleared").unwrap_or(false);
    let gated_read_absorbed =
        verification_bool(observation, "web_pipeline_gated_read_absorbed").unwrap_or(false);

    if approval_pending_cleared
        && gated_read_absorbed
        && !denied
        && !awaiting_sudo
        && !awaiting_clarification
    {
        return false;
    }

    denied || ((requires_approval || awaiting_sudo || awaiting_clarification) && !approved)
}

pub fn has_routing_failure_class(observation: &RunObservation, class_name: &str) -> bool {
    observation
        .routing_failure_classes
        .iter()
        .any(|value| value.eq_ignore_ascii_case(class_name))
}

pub fn has_failure_class(observation: &RunObservation, class_name: &str) -> bool {
    has_routing_failure_class(observation, class_name)
        || observation
            .action_error_classes
            .iter()
            .any(|value| value.eq_ignore_ascii_case(class_name))
        || has_verification_pair(observation, "failure_class", class_name)
        || verification_values(observation, "error_class")
            .iter()
            .any(|value| value.eq_ignore_ascii_case(class_name))
}

pub fn has_typed_contract_failure_evidence(observation: &RunObservation) -> bool {
    let cec_contract_gate_failed =
        latest_cec_receipt(observation, "completion_gate", "contract_gate")
            .is_some_and(|receipt| !receipt.satisfied);
    if cec_contract_gate_failed {
        return true;
    }

    observation
        .action_error_classes
        .iter()
        .any(|class_name| is_contract_error_class(class_name))
        || observation
            .routing_failure_classes
            .iter()
            .any(|class_name| is_contract_error_class(class_name))
}

pub fn is_retry_blocked_terminal(observation: &RunObservation) -> bool {
    verification_bool(observation, "attempt_retry_blocked_without_change").unwrap_or(false)
}

pub fn is_timeout_terminal(observation: &RunObservation) -> bool {
    has_failure_class(observation, "TimeoutOrHang")
}

pub fn has_contract_failure_evidence(observation: &RunObservation) -> bool {
    has_typed_contract_failure_evidence(observation)
}

pub fn is_no_effect_after_action_class(value: &str) -> bool {
    value.trim().eq_ignore_ascii_case("NoEffectAfterAction")
}

pub fn action_has_hard_error_class(entry: &ActionEvidence) -> bool {
    entry
        .error_class
        .as_deref()
        .map(|class_name| !is_no_effect_after_action_class(class_name))
        .unwrap_or(false)
}

fn is_contract_error_class(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "executioncontractviolation"
            | "discoverymissing"
            | "synthesisfailed"
            | "executionfailedterminal"
            | "verificationmissing"
            | "postconditionfailed"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_observation() -> RunObservation {
        RunObservation {
            case_id: "case".to_string(),
            query: "query".to_string(),
            run_timestamp_ms: 1,
            run_timestamp_iso_utc: "2026-03-07T00:00:00Z".to_string(),
            elapsed_ms: 0,
            completed: false,
            failed: false,
            final_status: String::new(),
            terminal_pause_reason: None,
            terminal_failure_reason: None,
            final_reply: String::new(),
            chat_reply_count: 0,
            action_tools: Vec::new(),
            planned_tool_calls: Vec::new(),
            routing_tools: Vec::new(),
            workload_tools: Vec::new(),
            routing_policy_decisions: Vec::new(),
            routing_failure_classes: Vec::new(),
            routing_stop_condition_hits: 0,
            verification_checks: Vec::new(),
            verification_facts: Vec::new(),
            approval_required_events: 0,
            action_evidence: Vec::new(),
            action_error_classes: Vec::new(),
            command_history_evidence: Vec::new(),
            cec_receipts: Vec::new(),
            intent_resolution_evidence: Vec::new(),
            environment_receipts: Vec::new(),
            web: None,
            screenshot: None,
            mail: None,
            google: None,
            event_excerpt: Vec::new(),
            kernel_event_count: 0,
            kernel_log_lines: Vec::new(),
        }
    }

    #[test]
    fn environment_receipt_queries_do_not_fallback_to_verification_facts() {
        let mut observation = empty_observation();
        observation.verification_facts.push(VerificationFact {
            key: "env_receipt::fixture_mode".to_string(),
            value: Some("string_fallback".to_string()),
        });

        assert_eq!(
            environment_value(&observation, "env_receipt::fixture_mode"),
            None
        );
        assert_eq!(
            verification_value(&observation, "env_receipt::fixture_mode"),
            None
        );
        assert!(!has_verification_pair(
            &observation,
            "env_receipt::fixture_mode",
            "string_fallback"
        ));
    }

    #[test]
    fn environment_receipt_queries_read_typed_environment_observations() {
        let mut observation = empty_observation();
        observation
            .environment_receipts
            .push(EnvironmentReceiptObservation {
                key: "fixture_mode".to_string(),
                observed_values: vec!["typed_runtime".to_string()],
                probe_source: Some("harness.fixture".to_string()),
                timestamp_ms: Some(42),
                satisfied: Some(true),
            });

        assert_eq!(
            environment_value(&observation, "env_receipt::fixture_mode").as_deref(),
            Some("typed_runtime")
        );
        assert_eq!(
            verification_value(&observation, "env_receipt::fixture_mode").as_deref(),
            Some("typed_runtime")
        );
        assert_eq!(
            verification_value(&observation, "env_receipt::fixture_mode_probe_source").as_deref(),
            Some("harness.fixture")
        );
        assert_eq!(
            verification_bool(&observation, "env_receipt::fixture_mode_satisfied"),
            Some(true)
        );
        assert_eq!(
            verification_u64(&observation, "env_receipt::fixture_mode_timestamp_ms"),
            Some(42)
        );
    }

    #[test]
    fn absorbed_web_read_gates_do_not_count_as_unresolved_approval() {
        let mut observation = empty_observation();
        observation.approval_required_events = 1;
        observation
            .routing_policy_decisions
            .push("require_approval".to_string());
        observation.verification_facts.push(VerificationFact {
            key: "approval_pending_cleared".to_string(),
            value: Some("true".to_string()),
        });
        observation.verification_facts.push(VerificationFact {
            key: "web_pipeline_gated_read_absorbed".to_string(),
            value: Some("true".to_string()),
        });

        assert!(!has_unresolved_approval_gate(&observation));
    }

    #[test]
    fn cec_receipt_latest_values_returns_full_latest_timestamp_group() {
        let mut observation = empty_observation();
        observation.cec_receipts = vec![
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "selected_source_url".to_string(),
                satisfied: true,
                timestamp_ms: 10,
                probe_source: None,
                observed_value: Some("https://example.com/older".to_string()),
                evidence_type: Some("url".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "selected_source_url".to_string(),
                satisfied: true,
                timestamp_ms: 20,
                probe_source: None,
                observed_value: Some("https://example.com/one".to_string()),
                evidence_type: Some("url".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "local_business_entity_name".to_string(),
                satisfied: true,
                timestamp_ms: 20,
                probe_source: None,
                observed_value: Some("Example Restaurant".to_string()),
                evidence_type: Some("entity_name".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "selected_source_url".to_string(),
                satisfied: true,
                timestamp_ms: 20,
                probe_source: None,
                observed_value: Some("https://example.com/two".to_string()),
                evidence_type: Some("url".to_string()),
                provider_id: None,
            },
        ];

        assert_eq!(
            cec_receipt_latest_values(&observation, "verification", "selected_source_url"),
            vec![
                "https://example.com/one".to_string(),
                "https://example.com/two".to_string()
            ]
        );
    }

    #[test]
    fn cec_receipt_latest_values_returns_latest_contiguous_batch_when_timestamps_drift() {
        let mut observation = empty_observation();
        observation.cec_receipts = vec![
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "local_business_menu_surface_source_url".to_string(),
                satisfied: true,
                timestamp_ms: 10,
                probe_source: None,
                observed_value: Some("https://example.com/older".to_string()),
                evidence_type: Some("url".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "story_slot_floor".to_string(),
                satisfied: true,
                timestamp_ms: 11,
                probe_source: None,
                observed_value: Some("3".to_string()),
                evidence_type: Some("scalar".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "local_business_menu_surface_source_url".to_string(),
                satisfied: true,
                timestamp_ms: 20,
                probe_source: None,
                observed_value: Some("https://example.com/one".to_string()),
                evidence_type: Some("url".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "local_business_menu_surface_source_url".to_string(),
                satisfied: true,
                timestamp_ms: 21,
                probe_source: None,
                observed_value: Some("https://example.com/two".to_string()),
                evidence_type: Some("url".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "verification".to_string(),
                key: "local_business_menu_surface_source_url".to_string(),
                satisfied: true,
                timestamp_ms: 22,
                probe_source: None,
                observed_value: Some("https://example.com/three".to_string()),
                evidence_type: Some("url".to_string()),
                provider_id: None,
            },
        ];

        assert_eq!(
            cec_receipt_latest_values(
                &observation,
                "verification",
                "local_business_menu_surface_source_url",
            ),
            vec![
                "https://example.com/one".to_string(),
                "https://example.com/two".to_string(),
                "https://example.com/three".to_string(),
            ]
        );
    }

    #[test]
    fn cec_receipt_satisfied_reads_receipt_state_not_observed_value_payload() {
        let mut observation = empty_observation();
        observation.cec_receipts = vec![CecReceiptEvidence {
            contract_version: "cec.v0.5".to_string(),
            stage: "verification".to_string(),
            key: "local_business_menu_inventory_floor".to_string(),
            satisfied: true,
            timestamp_ms: 10,
            probe_source: Some("web.pipeline.completion.local_business_menu_inventory.v1".to_string()),
            observed_value: Some(
                "selected_menu_inventory_sources=3;total_menu_inventory_items=15;required_story_floor=3;required_items_per_source=2"
                    .to_string(),
            ),
            evidence_type: Some("summary".to_string()),
            provider_id: None,
        }];

        assert_eq!(
            cec_receipt_satisfied(
                &observation,
                "verification",
                "local_business_menu_inventory_floor",
            ),
            Some(true)
        );
        assert_eq!(
            cec_receipt_bool(
                &observation,
                "verification",
                "local_business_menu_inventory_floor",
            ),
            None
        );
    }

    #[test]
    fn typed_contract_failure_evidence_ignores_superseded_contract_gate_failure() {
        let mut observation = empty_observation();
        observation.cec_receipts = vec![
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "completion_gate".to_string(),
                key: "contract_gate".to_string(),
                satisfied: false,
                timestamp_ms: 10,
                probe_source: Some("web.pipeline.completion.final_output.v1".to_string()),
                observed_value: Some("false".to_string()),
                evidence_type: Some("bool".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "completion_gate".to_string(),
                key: "contract_gate".to_string(),
                satisfied: true,
                timestamp_ms: 20,
                probe_source: Some("web.pipeline.completion.final_output.v1".to_string()),
                observed_value: Some("true".to_string()),
                evidence_type: Some("bool".to_string()),
                provider_id: None,
            },
        ];

        assert!(!has_typed_contract_failure_evidence(&observation));
    }

    #[test]
    fn typed_contract_failure_evidence_respects_latest_contract_gate_failure() {
        let mut observation = empty_observation();
        observation.cec_receipts = vec![
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "completion_gate".to_string(),
                key: "contract_gate".to_string(),
                satisfied: true,
                timestamp_ms: 10,
                probe_source: Some("web.pipeline.completion.final_output.v1".to_string()),
                observed_value: Some("true".to_string()),
                evidence_type: Some("bool".to_string()),
                provider_id: None,
            },
            CecReceiptEvidence {
                contract_version: "cec.v0.5".to_string(),
                stage: "completion_gate".to_string(),
                key: "contract_gate".to_string(),
                satisfied: false,
                timestamp_ms: 20,
                probe_source: Some("web.pipeline.completion.final_output.v1".to_string()),
                observed_value: Some("false".to_string()),
                evidence_type: Some("bool".to_string()),
                provider_id: None,
            },
        ];

        assert!(has_typed_contract_failure_evidence(&observation));
    }
}
