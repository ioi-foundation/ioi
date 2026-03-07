use ioi_types::app::agentic::IntentScopeProfile;

use super::super::types::{
    has_cec_receipt, has_typed_contract_failure_evidence, observation_has_any_tool_name,
    truncate_chars, ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation,
};

pub fn case() -> QueryCase {
    QueryCase {
        id: "top_news_headlines",
        query: "Tell me today's top news headlines.",
        success_definition: "Return today's top headlines with typed currentness, provider-discovery, story-slot, citation-floor, and source-quality evidence.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 90,
        max_steps: 18,
        min_local_score: 0.80,
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

    let provider_candidate_count = web.provider_candidates.len();
    let provider_success_count = web
        .provider_candidates
        .iter()
        .filter(|candidate| candidate.success && candidate.source_count > 0)
        .count();
    let provider_selected_count = web
        .provider_candidates
        .iter()
        .filter(|candidate| candidate.selected && candidate.source_count > 0)
        .count();

    let source_count = web.selected_source_count.unwrap_or(0);
    let distinct_domains = web.selected_source_distinct_domains.unwrap_or(0);
    let story_slots_observed = web.story_slots_observed.unwrap_or(0);
    let min_sources = web.min_sources.unwrap_or(0);
    let sources_success = web.sources_success.unwrap_or(0);
    let currentness_required = web.currentness_required.unwrap_or(false);
    let source_floor_met = web.source_floor_met.unwrap_or(false);
    let quality_floor_met = web.selected_source_quality_floor_met.unwrap_or(false);
    let story_slot_floor_met = web.story_slot_floor_met.unwrap_or(false);
    let story_citation_floor_met = web.story_citation_floor_met.unwrap_or(false);

    let completion_gate_satisfied =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let completion_evidence_present =
        obs.completed && !obs.failed && obs.chat_reply_count > 0 && completion_gate_satisfied;
    let provider_discovery_evidence_present =
        provider_candidate_count > 0 && provider_success_count > 0 && provider_selected_count > 0;
    let currentness_evidence_present = currentness_required;
    let source_floor_receipts_present =
        source_floor_met && min_sources >= 3 && sources_success >= min_sources;
    let selected_source_quality_receipts_present =
        quality_floor_met && source_count >= 3 && distinct_domains >= 3;
    let story_floor_receipts_present =
        story_slot_floor_met && story_citation_floor_met && story_slots_observed >= 3;
    let tool_and_route_path_evidence_present = web_path_seen(obs);
    let contract_failure_markers_absent = !has_typed_contract_failure_evidence(obs);

    let independent_channel_count = [
        completion_evidence_present,
        provider_discovery_evidence_present,
        currentness_evidence_present,
        source_floor_receipts_present,
        selected_source_quality_receipts_present,
        story_floor_receipts_present,
        tool_and_route_path_evidence_present,
        contract_failure_markers_absent,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} completion_gate_satisfied={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                completion_gate_satisfied
            ),
        ),
        LocalCheck::new(
            "provider_discovery_evidence_present",
            provider_discovery_evidence_present,
            format!(
                "provider_candidate_count={} provider_success_count={} provider_selected_count={}",
                provider_candidate_count, provider_success_count, provider_selected_count
            ),
        ),
        LocalCheck::new(
            "currentness_evidence_present",
            currentness_evidence_present,
            truncate_chars(
                &format!(
                    "currentness_required={} query_contract={}",
                    currentness_required,
                    web.query_contract.clone().unwrap_or_default()
                ),
                180,
            ),
        ),
        LocalCheck::new(
            "source_floor_receipts_present",
            source_floor_receipts_present,
            format!(
                "min_sources={} sources_success={} source_floor_met={}",
                min_sources, sources_success, source_floor_met
            ),
        ),
        LocalCheck::new(
            "selected_source_quality_receipts_present",
            selected_source_quality_receipts_present,
            format!(
                "quality_floor_met={} selected_source_count={} distinct_domains={} selected_source_urls={:?}",
                quality_floor_met,
                source_count,
                distinct_domains,
                web.selected_source_urls
            ),
        ),
        LocalCheck::new(
            "story_floor_receipts_present",
            story_floor_receipts_present,
            format!(
                "story_slots_observed={} story_slot_floor_met={} story_citation_floor_met={}",
                story_slots_observed, story_slot_floor_met, story_citation_floor_met
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "routing_tools={:?} workload_tools={:?}",
                obs.routing_tools, obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            contract_failure_markers_absent,
            format!(
                "action_error_classes={:?} routing_failure_classes={:?}",
                obs.action_error_classes, obs.routing_failure_classes
            ),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_channel_count >= 8,
            format!("independent_channel_count={}", independent_channel_count),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn web_path_seen(obs: &RunObservation) -> bool {
    observation_has_any_tool_name(obs, &["web__search", "web__read"])
}
