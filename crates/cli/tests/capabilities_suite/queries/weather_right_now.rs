use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    has_cec_receipt, observation_has_any_tool_name, truncate_chars, ExecutionProfile, LocalCheck,
    LocalJudgeResult, QueryCase, RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "weather_right_now",
        query: "What's the weather like right now?",
        success_definition: "Answer current weather conditions for the active/inferred locality; concrete metrics are preferred, but explicitly caveated partial evidence is acceptable.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 75,
        max_steps: 16,
        min_local_score: 0.75,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn evaluate(obs: &RunObservation) -> LocalJudgeResult {
    let Some(web) = obs.web.as_ref() else {
        return LocalJudgeResult::from_checks(vec![
            LocalCheck::new(
                "web_observation_present",
                false,
                "missing typed web observation",
            ),
            LocalCheck::new(
                "completion_evidence_present",
                false,
                format!("status={} failed={}", obs.final_status, obs.failed),
            ),
        ]);
    };

    let currentness_required = web.currentness_required.unwrap_or(false);
    let source_floor_met = web.source_floor_met.unwrap_or(false);
    let quality_floor_met = web.selected_source_quality_floor_met.unwrap_or(false);
    let snapshot_grounded = web.single_snapshot_metric_grounding.unwrap_or(false);
    let single_snapshot_output_quality_met = has_cec_receipt(
        obs,
        "verification",
        "single_snapshot_rendered_layout",
        Some(true),
    ) && has_cec_receipt(
        obs,
        "verification",
        "single_snapshot_metric_line_floor",
        Some(true),
    ) && has_cec_receipt(
        obs,
        "verification",
        "single_snapshot_support_url_floor",
        Some(true),
    ) && has_cec_receipt(
        obs,
        "verification",
        "single_snapshot_read_backed_url_floor",
        Some(true),
    ) && has_cec_receipt(
        obs,
        "verification",
        "single_snapshot_temporal_signal",
        Some(true),
    );

    let web_path_observed = observation_has_any_tool_name(obs, &["web__search", "web__read"]);

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            obs.completed
                && !obs.failed
                && has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true)),
            format!(
                "status={} failed={} chat_reply_count={}",
                obs.final_status,
                obs.failed,
                obs.chat_reply_count
            ),
        ),
        LocalCheck::new(
            "current_weather_grounding_present",
            currentness_required && source_floor_met && quality_floor_met && snapshot_grounded,
            format!(
                "currentness_required={} source_floor_met={} quality_floor_met={} snapshot_grounded={} selected_source_urls={:?}",
                currentness_required,
                source_floor_met,
                quality_floor_met,
                snapshot_grounded,
                web.selected_source_urls
            ),
        ),
        LocalCheck::new(
            "single_snapshot_output_quality_present",
            single_snapshot_output_quality_met,
            format!(
                "rendered_layout_ok={} metric_line_floor_ok={} support_url_floor_ok={} read_backed_url_floor_ok={} temporal_signal_ok={}",
                has_cec_receipt(obs, "verification", "single_snapshot_rendered_layout", Some(true)),
                has_cec_receipt(obs, "verification", "single_snapshot_metric_line_floor", Some(true)),
                has_cec_receipt(obs, "verification", "single_snapshot_support_url_floor", Some(true)),
                has_cec_receipt(obs, "verification", "single_snapshot_read_backed_url_floor", Some(true)),
                has_cec_receipt(obs, "verification", "single_snapshot_temporal_signal", Some(true)),
            ),
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
            "runtime_locality_alignment_present",
            web.runtime_locality_alignment.unwrap_or(true),
            truncate_chars(&web.query_contract.clone().unwrap_or_default(), 100),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}
