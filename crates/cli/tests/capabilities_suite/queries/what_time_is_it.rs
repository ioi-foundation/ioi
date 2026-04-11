use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    cec_receipt_value, has_cec_receipt, observation_has_any_tool_name, truncate_chars,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "what_time_is_it",
        query: "What time is it?",
        success_definition: "Provide the current time directly, ideally with a concrete timestamp or timezone context.",
        seeded_intent_id: "system.clock.read",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 45,
        max_steps: 10,
        min_local_score: 0.67,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let observed_timestamp =
        cec_receipt_value(obs, "verification", "clock_timestamp_observed").unwrap_or_default();
    let has_time_signal = !observed_timestamp.trim().is_empty()
        && has_cec_receipt(obs, "verification", "clock_timestamp_observed", Some(true));
    let time_tool_signal =
        observation_has_any_tool_name(obs, &["time", "shell__run", "shell__start"]);

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            obs.completed
                && !obs.failed
                && (has_time_signal
                    || has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true))),
            format!(
                "status={} failed={} command_history_count={} action_evidence_count={}",
                obs.final_status,
                obs.failed,
                obs.command_history_evidence.len(),
                obs.action_evidence.len()
            ),
        ),
        LocalCheck::new(
            "time_signal_in_runtime_evidence",
            has_time_signal,
            truncate_chars(&observed_timestamp, 120),
        ),
        LocalCheck::new(
            "time_or_command_tool_seen",
            time_tool_signal,
            format!(
                "action_tools={:?} routing_tools={:?}",
                obs.action_tools, obs.routing_tools
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
