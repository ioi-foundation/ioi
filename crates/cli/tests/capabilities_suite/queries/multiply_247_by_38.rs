use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    has_tool_with_token, is_retry_blocked_terminal, truncate_chars, ExecutionProfile, LocalCheck,
    LocalJudgeResult, QueryCase, RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "multiply_247_by_38",
        query: "What's 247 × 38?",
        success_definition: "Return the correct multiplication result (9386) clearly and directly.",
        seeded_intent_id: "math.eval",
        intent_scope: IntentScopeProfile::Conversation,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 30,
        max_steps: 8,
        min_local_score: 0.67,
        allow_retry_blocked_completion_with_local_evidence: true,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let lower_reply = obs.final_reply.to_ascii_lowercase();
    let action_output_concat = obs
        .action_evidence
        .iter()
        .map(|entry| entry.output_excerpt.as_str())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();

    let has_correct_answer = lower_reply.contains("9386")
        || lower_reply.contains("9,386")
        || action_output_concat.contains("9386")
        || action_output_concat.contains("9,386");

    let no_web_retrieval_noise = !has_tool_with_token(&obs.routing_tools, "web__search")
        && !has_tool_with_token(&obs.routing_tools, "web__read")
        && !has_tool_with_token(&obs.workload_tools, "web__search")
        && !has_tool_with_token(&obs.workload_tools, "web__read");

    let math_tool_used = has_tool_with_token(&obs.routing_tools, "math__eval")
        || has_tool_with_token(&obs.action_tools, "math__eval");

    let paused_retry_blocked = is_retry_blocked_terminal(obs);
    let completed_with_result_channel = (obs.completed && !obs.action_evidence.is_empty())
        || (paused_retry_blocked && has_correct_answer && math_tool_used);

    let checks = vec![
        LocalCheck::new(
            "completed_with_result_channel",
            completed_with_result_channel,
            format!(
                "status={} paused_retry_blocked={} reply_len={} action_evidence_count={}",
                obs.final_status,
                paused_retry_blocked,
                obs.final_reply.chars().count(),
                obs.action_evidence.len()
            ),
        ),
        LocalCheck::new(
            "correct_answer_present",
            has_correct_answer,
            truncate_chars(
                &format!("{} {}", obs.final_reply, action_output_concat),
                120,
            ),
        ),
        LocalCheck::new(
            "math_tool_used",
            math_tool_used,
            format!(
                "routing_tools={:?} action_tools={:?}",
                obs.routing_tools, obs.action_tools
            ),
        ),
        LocalCheck::new(
            "no_web_retrieval_noise",
            no_web_retrieval_noise,
            format!(
                "routing_tools={:?} workload_tools={:?}",
                obs.routing_tools, obs.workload_tools
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
