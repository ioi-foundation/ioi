use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::judge::ArbiterVerdict;

pub type LocalSniffFn = fn(&RunObservation) -> LocalJudgeResult;

#[derive(Clone)]
pub struct QueryCase {
    pub id: &'static str,
    pub query: &'static str,
    pub success_definition: &'static str,
    pub seeded_intent_id: &'static str,
    pub intent_scope: IntentScopeProfile,
    pub expected_pass: bool,
    pub sla_seconds: u64,
    pub max_steps: u32,
    pub min_local_score: f64,
    pub allow_retry_blocked_completion_with_local_evidence: bool,
    pub local_sniff: LocalSniffFn,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionEvidence {
    pub tool_name: String,
    pub agent_status: String,
    pub output_excerpt: String,
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
    pub final_reply: String,
    pub chat_reply_count: usize,
    pub action_tools: Vec<String>,
    pub routing_tools: Vec<String>,
    pub workload_tools: Vec<String>,
    pub verification_checks: Vec<String>,
    pub approval_required_events: usize,
    pub action_evidence: Vec<ActionEvidence>,
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

pub fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

pub fn has_tool_with_token(tools: &[String], token: &str) -> bool {
    tools
        .iter()
        .any(|tool| tool.to_ascii_lowercase().contains(token))
}

pub fn truncate_chars(input: &str, max_chars: usize) -> String {
    let compact = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if compact.chars().count() <= max_chars {
        compact
    } else {
        compact.chars().take(max_chars).collect::<String>() + "..."
    }
}
