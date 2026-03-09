use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    cec_receipt_value, is_retry_blocked_terminal, observation_has_tool_name,
    observation_has_tool_namespace, truncate_chars, ExecutionProfile, LocalCheck, LocalJudgeResult,
    QueryCase, RunObservation, ToolNamespace,
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
    let math_result = cec_receipt_value(obs, "verification", "math_result").unwrap_or_default();
    let has_correct_answer = math_result.trim() == "9386";
    let no_web_retrieval_noise = !observation_has_tool_namespace(obs, ToolNamespace::Web);
    let math_tool_used = observation_has_tool_name(obs, "math__eval");

    let paused_retry_blocked = is_retry_blocked_terminal(obs);
    let completed_with_result_channel = (obs.completed && !obs.action_evidence.is_empty())
        || (paused_retry_blocked && has_correct_answer && math_tool_used);

    let checks = vec![
        LocalCheck::new(
            "completed_with_result_channel",
            completed_with_result_channel && !obs.failed,
            format!(
                "status={} failed={} paused_retry_blocked={} command_history_count={} action_evidence_count={}",
                obs.final_status,
                obs.failed,
                paused_retry_blocked,
                obs.command_history_evidence.len(),
                obs.action_evidence.len()
            ),
        ),
        LocalCheck::new(
            "correct_answer_present",
            has_correct_answer,
            truncate_chars(&format!("math_result={}", math_result), 120),
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
