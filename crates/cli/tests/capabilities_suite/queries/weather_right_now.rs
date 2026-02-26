use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    contains_any, has_tool_with_token, truncate_chars, LocalCheck, LocalJudgeResult, QueryCase,
    RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "weather_right_now",
        query: "What's the weather like right now?",
        success_definition: "Answer current weather conditions for the active/inferred locality; concrete metrics are preferred, but explicitly caveated partial evidence is acceptable.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        expected_pass: true,
        sla_seconds: 75,
        max_steps: 16,
        min_local_score: 0.75,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let lower_reply = obs.final_reply.to_ascii_lowercase();

    let has_weather_language = contains_any(
        &lower_reply,
        &[
            "weather",
            "temperature",
            "overcast",
            "cloud",
            "rain",
            "storm",
            "sunny",
            "clear",
            "wind",
            "humidity",
            "forecast",
        ],
    ) || obs.final_reply.contains('°');

    let web_path_observed = has_tool_with_token(&obs.routing_tools, "web__search")
        || has_tool_with_token(&obs.routing_tools, "web__read")
        || has_tool_with_token(&obs.workload_tools, "web__search")
        || has_tool_with_token(&obs.workload_tools, "web__read");

    let has_currentness_signal = contains_any(
        &lower_reply,
        &["right now", "current", "currently", "as of", "today", "utc"],
    );

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
            "weather_language_present",
            has_weather_language,
            truncate_chars(&obs.final_reply, 140),
        ),
        LocalCheck::new(
            "web_retrieval_path_seen",
            web_path_observed,
            format!(
                "routing_tools={:?} workload_tools={:?}",
                obs.routing_tools, obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "currentness_signal_present",
            has_currentness_signal,
            truncate_chars(&obs.final_reply, 100),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
