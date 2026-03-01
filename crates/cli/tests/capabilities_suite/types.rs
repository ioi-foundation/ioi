use ioi_types::app::agentic::IntentScopeProfile;
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
    pub provider_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationFact {
    pub key: String,
    pub value: Option<String>,
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

pub fn has_verification_check(observation: &RunObservation, expected: &str) -> bool {
    observation
        .verification_checks
        .iter()
        .any(|check| check.eq_ignore_ascii_case(expected))
}

pub fn has_verification_pair(observation: &RunObservation, key: &str, value: &str) -> bool {
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
    observation
        .verification_facts
        .iter()
        .find(|fact| fact.key.eq_ignore_ascii_case(key))
        .and_then(|fact| fact.value.clone())
}

pub fn verification_values(observation: &RunObservation, key: &str) -> Vec<String> {
    observation
        .verification_facts
        .iter()
        .filter(|fact| fact.key.eq_ignore_ascii_case(key))
        .filter_map(|fact| fact.value.clone())
        .collect()
}

pub fn verification_bool(observation: &RunObservation, key: &str) -> Option<bool> {
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
    verification_value(observation, key).and_then(|value| value.trim().parse::<u64>().ok())
}

pub fn verification_usize(observation: &RunObservation, key: &str) -> Option<usize> {
    verification_value(observation, key).and_then(|value| value.trim().parse::<usize>().ok())
}

pub fn max_verification_usize(observation: &RunObservation, key: &str) -> Option<usize> {
    verification_values(observation, key)
        .into_iter()
        .filter_map(|value| value.trim().parse::<usize>().ok())
        .max()
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

pub fn is_retry_blocked_terminal(observation: &RunObservation) -> bool {
    observation
        .terminal_pause_reason
        .as_ref()
        .map(|reason| {
            reason
                .to_ascii_lowercase()
                .contains("retry blocked: unchanged attemptkey")
        })
        .unwrap_or(false)
        || observation
            .final_status
            .to_ascii_lowercase()
            .contains("retry blocked: unchanged attemptkey")
}

pub fn is_timeout_terminal(observation: &RunObservation) -> bool {
    has_failure_class(observation, "TimeoutOrHang")
        || observation
            .terminal_pause_reason
            .as_ref()
            .map(|reason| reason.to_ascii_lowercase().contains("timeoutorhang"))
            .unwrap_or(false)
        || observation
            .terminal_failure_reason
            .as_ref()
            .map(|reason| reason.to_ascii_lowercase().contains("timeoutorhang"))
            .unwrap_or(false)
        || observation
            .final_status
            .to_ascii_lowercase()
            .contains("timeoutorhang")
}

pub fn has_contract_failure_evidence(observation: &RunObservation) -> bool {
    let cec_contract_gate_failed = observation.cec_receipts.iter().any(|receipt| {
        receipt.stage.eq_ignore_ascii_case("completion_gate")
            && receipt.key.eq_ignore_ascii_case("contract_gate")
            && !receipt.satisfied
    });
    if cec_contract_gate_failed {
        return true;
    }

    if verification_bool(observation, "execution_contract_gate_blocked").unwrap_or(false)
        || verification_bool(observation, "cec_terminal_error").unwrap_or(false)
    {
        return true;
    }

    if verification_value(observation, "failed_stage")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || verification_value(observation, "missing_receipts")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        || verification_value(observation, "missing_postconditions")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
    {
        return true;
    }

    if observation
        .action_error_classes
        .iter()
        .any(|class_name| is_contract_error_class(class_name))
    {
        return true;
    }

    if observation
        .routing_failure_classes
        .iter()
        .any(|class_name| is_contract_error_class(class_name))
    {
        return true;
    }

    if verification_values(observation, "error_class")
        .iter()
        .any(|class_name| is_contract_error_class(class_name))
        || verification_values(observation, "base_error_class")
            .iter()
            .any(|class_name| is_contract_error_class(class_name))
    {
        return true;
    }

    false
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
