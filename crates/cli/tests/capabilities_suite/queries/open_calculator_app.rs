use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    contains_any, has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "open_calculator_app",
        query: "Open the Calculator app.",
        success_definition: "Launch calculator successfully and acknowledge completion clearly.",
        seeded_intent_id: "app.launch",
        intent_scope: IntentScopeProfile::AppLaunch,
        expected_pass: true,
        sla_seconds: 45,
        max_steps: 10,
        min_local_score: 0.67,
        allow_retry_blocked_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let lower_reply = obs.final_reply.to_ascii_lowercase();

    let reply_acknowledges_launch = contains_any(
        &lower_reply,
        &["opened", "launch", "launched", "open", "calculator"],
    );

    let launch_tool_seen = has_tool_with_token(&obs.action_tools, "launch")
        || has_tool_with_token(&obs.routing_tools, "launch")
        || has_tool_with_token(&obs.action_tools, "sys__exec")
        || has_tool_with_token(&obs.routing_tools, "sys__exec")
        || has_tool_with_token(&obs.action_tools, "app")
        || has_tool_with_token(&obs.routing_tools, "app");

    let calculator_evidence_seen = contains_any(&lower_reply, &["calculator"])
        || obs.action_evidence.iter().any(|entry| {
            entry
                .output_excerpt
                .to_ascii_lowercase()
                .contains("calculator")
        });

    let checks = vec![
        LocalCheck::new(
            "completed_with_reply",
            obs.completed && !obs.final_reply.trim().is_empty(),
            format!(
                "status={} reply_len={}",
                obs.final_status,
                obs.final_reply.chars().count()
            ),
        ),
        LocalCheck::new(
            "launch_or_open_acknowledged",
            reply_acknowledges_launch,
            truncate_chars(&obs.final_reply, 120),
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
            calculator_evidence_seen,
            format!(
                "reply_excerpt={} action_evidence_count={}",
                truncate_chars(&obs.final_reply, 80),
                obs.action_evidence.len()
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
