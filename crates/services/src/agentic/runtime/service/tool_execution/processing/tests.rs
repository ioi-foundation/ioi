use super::{duplicate_command_completion_summary, should_fail_fast_web_timeout};
use crate::agentic::runtime::service::recovery::anti_loop::FailureClass;
use crate::agentic::runtime::service::tool_execution::command_contract::{
    execution_contract_violation_error, upsert_structured_field, TARGET_UTC_MARKER,
};
use crate::agentic::runtime::types::CommandExecution;
use ioi_types::app::agentic::{
    AgentTool, IntentConfidenceBand, IntentScopeProfile, ResolvedIntentState,
};

fn resolved(scope: IntentScopeProfile) -> ResolvedIntentState {
    ResolvedIntentState {
        intent_id: "test".to_string(),
        scope,
        band: IntentConfidenceBand::High,
        score: 0.92,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "low".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "v1".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "cosine".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "v1".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: None,
        constrained: false,
    }
}

#[test]
fn web_research_timeout_tools_fail_fast() {
    let intent = resolved(IntentScopeProfile::WebResearch);
    assert!(should_fail_fast_web_timeout(
        Some(&intent),
        "web__search",
        FailureClass::TimeoutOrHang,
        false
    ));
    assert!(should_fail_fast_web_timeout(
        Some(&intent),
        "web__read",
        FailureClass::TimeoutOrHang,
        false
    ));
    assert!(should_fail_fast_web_timeout(
        Some(&intent),
        "browser__navigate",
        FailureClass::TimeoutOrHang,
        false
    ));
    assert!(!should_fail_fast_web_timeout(
        Some(&intent),
        "web__read",
        FailureClass::TimeoutOrHang,
        true
    ));
}

#[test]
fn non_matching_cases_do_not_fail_fast() {
    let web = resolved(IntentScopeProfile::WebResearch);
    let convo = resolved(IntentScopeProfile::Conversation);

    assert!(!should_fail_fast_web_timeout(
        Some(&web),
        "file__list",
        FailureClass::TimeoutOrHang,
        false
    ));
    assert!(!should_fail_fast_web_timeout(
        Some(&convo),
        "browser__navigate",
        FailureClass::TimeoutOrHang,
        false
    ));
    assert!(!should_fail_fast_web_timeout(
        Some(&convo),
        "web__search",
        FailureClass::TimeoutOrHang,
        false
    ));
    assert!(!should_fail_fast_web_timeout(
        Some(&web),
        "web__search",
        FailureClass::UnexpectedState,
        false
    ));
}

#[test]
fn duplicate_timer_exec_terminalizes_with_structured_evidence() {
    let tool = AgentTool::SysExec {
        command: "sleep".to_string(),
        args: vec!["900".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: true,
    };
    let history = CommandExecution {
        command: "sleep 900".to_string(),
        exit_code: 0,
        stdout: "Launched background process 'sleep' (PID: 167007)".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_771_931_911_073,
        step_index: 0,
    };

    let summary = duplicate_command_completion_summary(&tool, Some(&history))
        .expect("expected deterministic duplicate completion");
    assert!(summary.contains("Timer scheduled."));
    assert!(summary.contains("Mechanism: Detached shell__run command 'sleep 900'"));
    assert!(summary.contains("Run timestamp (UTC):"));
    assert!(summary.contains("Target UTC:"));
}

#[test]
fn duplicate_timer_exec_terminalizes_with_script_command_and_redacted_history() {
    let tool = AgentTool::SysExec {
        command: "bash".to_string(),
        args: vec![
            "-lc".to_string(),
            "nohup sh -c 'sleep 900 && notify-send Timer Done' &".to_string(),
        ],
        stdin: None,
        wait_ms_before_async: None,
        detach: true,
    };
    let history = CommandExecution {
        command: "[REDACTED_PII]".to_string(),
        exit_code: 0,
        stdout: "Launched background process 'bash' (PID: 3210)".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_771_931_911_073,
        step_index: 1,
    };

    let summary = duplicate_command_completion_summary(&tool, Some(&history))
        .expect("expected deterministic duplicate completion for script timer");
    assert!(summary.contains("Timer scheduled."));
    assert!(summary.contains("Mechanism: Detached shell__run command 'bash -lc"));
    assert!(summary.contains("Run timestamp (UTC):"));
    assert!(summary.contains("Target UTC:"));
}

#[test]
fn duplicate_timer_exec_requires_detached_command() {
    let tool = AgentTool::SysExec {
        command: "sleep".to_string(),
        args: vec!["900".to_string()],
        stdin: None,
        wait_ms_before_async: None,
        detach: false,
    };
    let history = CommandExecution {
        command: "sleep 900".to_string(),
        exit_code: 0,
        stdout: "Launched background process 'sleep' (PID: 167007)".to_string(),
        stderr: String::new(),
        timestamp_ms: 1_771_931_911_073,
        step_index: 0,
    };

    assert!(duplicate_command_completion_summary(&tool, Some(&history)).is_none());
}

#[test]
fn upsert_structured_field_replaces_inline_marker_segment() {
    let summary = "Timer set. Target UTC: 2023-10-05T14:15:00Z.";
    let updated = upsert_structured_field(summary, TARGET_UTC_MARKER, "2026-02-24T13:23:28.938Z");

    assert!(!updated.contains("2023-10-05T14:15:00Z"));
    assert!(updated.contains("Target UTC: 2026-02-24T13:23:28.938Z"));
    assert!(updated.contains("Timer set."));
}

#[test]
fn execution_contract_violation_uses_spec_error_class() {
    let message = execution_contract_violation_error("evidence::verification=true");
    assert!(message.starts_with("ERROR_CLASS=ExecutionContractViolation "));
    assert!(message.contains("detail_class=VerificationMissing"));
}
