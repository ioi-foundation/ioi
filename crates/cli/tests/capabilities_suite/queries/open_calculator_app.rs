use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    has_cec_receipt, observation_has_any_tool_name, truncate_chars, ExecutionProfile, LocalCheck,
    LocalJudgeResult, QueryCase, RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "open_calculator_app",
        query: "Open the Calculator app.",
        success_definition: "Launch calculator successfully and acknowledge completion clearly.",
        seeded_intent_id: "app.launch",
        intent_scope: IntentScopeProfile::AppLaunch,
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
    let launch_action_completed = obs.action_evidence.iter().any(|entry| {
        entry.tool_name.eq_ignore_ascii_case("os__launch_app")
            && entry.agent_status.eq_ignore_ascii_case("completed")
            && entry.error_class.is_none()
    });
    let launch_plan_observed = obs.planned_tool_calls.iter().any(|entry| {
        entry.tool_name.eq_ignore_ascii_case("os__launch_app")
            && entry
                .arguments
                .get("app_name")
                .and_then(|value| value.as_str())
                .map(|value| value.eq_ignore_ascii_case("calculator"))
                .unwrap_or(false)
    });

    let launch_tool_seen =
        observation_has_any_tool_name(obs, &["os__launch_app", "sys__exec", "sys__exec_session"]);

    let completion_gate_satisfied =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            obs.completed
                && !obs.failed
                && obs.chat_reply_count > 0
                && launch_action_completed
                && completion_gate_satisfied,
            format!(
                "status={} failed={} chat_reply_count={} completion_gate_satisfied={} action_evidence_count={}",
                obs.final_status,
                obs.failed,
                obs.chat_reply_count,
                completion_gate_satisfied,
                obs.action_evidence.len()
            ),
        ),
        LocalCheck::new(
            "launch_action_observed",
            launch_action_completed && launch_plan_observed,
            format!(
                "planned_tool_calls={:?} action_evidence_samples={:?}",
                obs.planned_tool_calls
                    .iter()
                    .filter(|entry| entry.tool_name.eq_ignore_ascii_case("os__launch_app"))
                    .collect::<Vec<_>>(),
                obs.action_evidence.iter().take(2).collect::<Vec<_>>()
            ),
        ),
        LocalCheck::new(
            "system_launch_signal_seen",
            launch_tool_seen,
            format!(
                "action_tools={:?} routing_tools={:?}",
                obs.action_tools, obs.routing_tools
            ),
        ),
        LocalCheck::new(
            "calculator_named",
            launch_plan_observed,
            format!(
                "planned_launch_calls={}",
                truncate_chars(
                    &format!(
                        "{:?}",
                        obs.planned_tool_calls
                            .iter()
                            .filter(|entry| entry.tool_name.eq_ignore_ascii_case("os__launch_app"))
                            .collect::<Vec<_>>()
                    ),
                    120
                )
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
