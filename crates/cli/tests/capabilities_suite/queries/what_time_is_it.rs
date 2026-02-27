use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    contains_any, has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "what_time_is_it",
        query: "What time is it?",
        success_definition: "Provide the current time directly, ideally with a concrete timestamp or timezone context.",
        seeded_intent_id: "system.clock.read",
        intent_scope: IntentScopeProfile::CommandExecution,
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
    let has_time_signal = contains_hh_mm(&obs.final_reply)
        || contains_any(
            &lower_reply,
            &[
                " utc", " am", " pm", "gmt", "eastern", "pacific", "central", "mountain",
            ],
        );
    let time_tool_signal = has_tool_with_token(&obs.action_tools, "time")
        || has_tool_with_token(&obs.routing_tools, "time")
        || has_tool_with_token(&obs.action_tools, "sys__exec")
        || has_tool_with_token(&obs.routing_tools, "sys__exec")
        || has_tool_with_token(&obs.action_tools, "command")
        || has_tool_with_token(&obs.routing_tools, "command");

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
            "time_signal_in_reply",
            has_time_signal,
            truncate_chars(&obs.final_reply, 120),
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

fn contains_hh_mm(input: &str) -> bool {
    let bytes = input.as_bytes();
    if bytes.len() < 5 {
        return false;
    }

    for idx in 0..=bytes.len() - 5 {
        let window = &bytes[idx..idx + 5];
        if window[0].is_ascii_digit()
            && window[1].is_ascii_digit()
            && window[2] == b':'
            && window[3].is_ascii_digit()
            && window[4].is_ascii_digit()
        {
            return true;
        }
    }

    false
}
