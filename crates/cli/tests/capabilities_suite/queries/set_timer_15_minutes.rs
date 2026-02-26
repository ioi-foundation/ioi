use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    contains_any, has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "set_timer_15_minutes",
        query: "Set a timer for 15 minutes.",
        success_definition: "Create a 15-minute timer and confirm it is scheduled.",
        intent_scope: IntentScopeProfile::CommandExecution,
        expected_pass: true,
        sla_seconds: 50,
        max_steps: 12,
        min_local_score: 0.67,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let lower_reply = obs.final_reply.to_ascii_lowercase();

    let timer_acknowledged = contains_any(&lower_reply, &["timer", "scheduled", "set", "minutes"]);
    let includes_15_min_signal = contains_any(&lower_reply, &["15", "fifteen"])
        && contains_any(&lower_reply, &["minute", "min"]);

    let system_command_seen = has_tool_with_token(&obs.action_tools, "sys__exec")
        || has_tool_with_token(&obs.routing_tools, "sys__exec")
        || has_tool_with_token(&obs.action_tools, "command")
        || has_tool_with_token(&obs.routing_tools, "command");

    let sleep_or_timer_evidence = obs.action_evidence.iter().any(|entry| {
        let lower = entry.output_excerpt.to_ascii_lowercase();
        lower.contains("sleep 900")
            || lower.contains("timer")
            || lower.contains("15 minutes")
            || lower.contains("900")
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
            "timer_acknowledged",
            timer_acknowledged,
            truncate_chars(&obs.final_reply, 120),
        ),
        LocalCheck::new(
            "15_minute_signal_present",
            includes_15_min_signal,
            truncate_chars(&obs.final_reply, 120),
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
