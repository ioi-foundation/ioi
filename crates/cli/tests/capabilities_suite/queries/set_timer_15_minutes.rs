use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    cec_receipt_usize, cec_receipt_value, has_cec_receipt, observation_has_any_tool_name,
    truncate_chars, ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "set_timer_15_minutes",
        query: "Set a timer for 15 minutes.",
        success_definition: "Create a 15-minute timer and confirm it is scheduled.",
        seeded_intent_id: "command.exec",
        intent_scope: IntentScopeProfile::CommandExecution,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 50,
        max_steps: 12,
        min_local_score: 0.67,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let timer_backend_observed =
        has_cec_receipt(obs, "execution", "timer_sleep_backend", Some(true));
    let notification_path_observed =
        has_cec_receipt(obs, "execution", "notification_path_armed", Some(true));
    let timer_delay_seconds = cec_receipt_usize(obs, "execution", "timer_delay_seconds")
        .or_else(|| {
            cec_receipt_value(obs, "execution", "timer_sleep_backend")
                .and_then(|value| value.trim().parse::<usize>().ok())
        })
        .unwrap_or(0);
    let includes_15_min_signal = timer_delay_seconds == 900;

    let system_command_seen =
        observation_has_any_tool_name(obs, &["sys__exec", "sys__exec_session"]);

    let sleep_or_timer_evidence =
        timer_backend_observed || notification_path_observed || timer_delay_seconds > 0;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            obs.completed
                && !obs.failed
                && has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true)),
            format!(
                "status={} failed={} cec_receipts={:?}",
                obs.final_status, obs.failed, obs.cec_receipts
            ),
        ),
        LocalCheck::new(
            "timer_contract_evidence_present",
            timer_backend_observed && notification_path_observed,
            truncate_chars(
                &format!("timer_delay_seconds={}", timer_delay_seconds),
                120,
            ),
        ),
        LocalCheck::new(
            "15_minute_signal_present",
            includes_15_min_signal,
            format!("timer_delay_seconds={}", timer_delay_seconds),
        ),
        LocalCheck::new(
            "system_command_path_seen",
            system_command_seen,
            format!(
                "action_tools={:?} routing_tools={:?}",
                obs.action_tools, obs.routing_tools
            ),
        ),
        LocalCheck::new(
            "sleep_or_timer_evidence_seen",
            sleep_or_timer_evidence,
            format!(
                "action_evidence_samples={:?}",
                obs.action_evidence.iter().take(2).collect::<Vec<_>>()
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
