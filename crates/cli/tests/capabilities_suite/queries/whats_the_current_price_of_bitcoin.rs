use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    cec_receipt_value, has_cec_receipt, has_cec_stage, has_typed_contract_failure_evidence,
    observation_has_tool_name, truncate_chars, ExecutionProfile, LocalCheck, LocalJudgeResult,
    QueryCase, RunObservation,
};

const CASE_ID: &str = "whats_the_current_price_of_bitcoin";

#[derive(Debug, Clone, Serialize)]
struct EvidenceReceipt {
    key: String,
    observed_value: String,
    probe_source: String,
    timestamp_ms: u64,
    satisfied: bool,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: "What's the current price of Bitcoin?",
        success_definition: "Return the current Bitcoin price with runtime-grounded web retrieval evidence, explicit single-snapshot metric grounding, and final source-quality receipts that satisfy the runtime retrieval contract.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 90,
        max_steps: 18,
        min_local_score: 1.0,
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
    let web_search_path_seen = observation_has_tool_name(obs, "web__search");
    let web_read_path_seen = observation_has_tool_name(obs, "web__read");
    let direct_fetch_path_seen = observation_has_tool_name(obs, "http__fetch");
    let tool_and_route_path_evidence_present =
        web_search_path_seen && web_read_path_seen && !direct_fetch_path_seen;

    let runtime_query_contract = web.query_contract.clone().unwrap_or_default();
    let retrieval_contract = web.retrieval_contract.as_ref();
    let required_independent_sources = retrieval_contract
        .map(|contract| contract.source_independence_min as usize)
        .unwrap_or_else(|| web.min_sources.unwrap_or(1).max(1));
    let runtime_locality_required = web.runtime_locality_required.unwrap_or(false);
    let runtime_locality_satisfied = !runtime_locality_required
        || web
            .runtime_locality_scope
            .as_ref()
            .map(|scope| !scope.trim().is_empty())
            .unwrap_or(false);
    let currentness_required = web.currentness_required.unwrap_or(false);
    let temporal_contract_receipts_present =
        has_cec_receipt(obs, "execution", "query_contract", Some(true))
            && has_cec_receipt(obs, "execution", "currentness_required", Some(true))
            && currentness_required
            && !runtime_query_contract.trim().is_empty()
            && (!runtime_locality_required || runtime_locality_satisfied);

    let web_min_sources = web.min_sources.unwrap_or(0);
    let web_sources_success = web.sources_success.unwrap_or(0);
    let source_floor_receipts_present =
        has_cec_receipt(obs, "verification", "source_floor", Some(true))
            && web.source_floor_met.unwrap_or(false)
            && web_min_sources >= required_independent_sources
            && web_sources_success >= required_independent_sources;

    let selected_source_quality_floor_met = web.selected_source_quality_floor_met.unwrap_or(false);
    let selected_source_subject_alignment_floor_met = web
        .selected_source_subject_alignment_floor_met
        .unwrap_or(false);
    let selected_source_urls = web.selected_source_urls.clone();
    let selected_source_count = web
        .selected_source_count
        .unwrap_or_else(|| selected_source_urls.len());
    let selected_source_distinct_domains = web.selected_source_distinct_domains.unwrap_or(0);
    let selected_source_quality_receipts_present = has_cec_receipt(
        obs,
        "verification",
        "selected_source_quality_floor",
        Some(true),
    ) && selected_source_quality_floor_met
        && selected_source_count >= required_independent_sources
        && selected_source_distinct_domains >= required_independent_sources;
    let selected_source_subject_alignment_receipts_present = has_cec_receipt(
        obs,
        "verification",
        "selected_source_subject_alignment_floor",
        Some(true),
    )
        && selected_source_subject_alignment_floor_met
        && !web.selected_source_subject_alignment_urls.is_empty();

    let final_story_slots_observed = web.story_slots_observed.unwrap_or(0);
    let final_story_citation_floor_met = web.story_citation_floor_met.unwrap_or(false);
    let final_comparison_required = false;
    let final_comparison_ready = web.comparison_ready.unwrap_or(true);
    let final_single_snapshot_metric_grounding =
        web.single_snapshot_metric_grounding.unwrap_or(false);
    let final_output_contract_ready = has_cec_receipt(
        obs,
        "verification",
        "final_output_contract_ready",
        Some(true),
    );
    let single_snapshot_output_quality_receipts_present = has_cec_receipt(
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
    let terminal_chat_reply_binding_digest =
        cec_receipt_value(obs, "postcondition", "terminal_chat_reply_binding").unwrap_or_default();
    let postcondition_terminal_chat_reply_binding_present = has_cec_receipt(
        obs,
        "postcondition",
        "terminal_chat_reply_binding",
        Some(true),
    );
    let terminal_chat_reply_binding_matches = postcondition_terminal_chat_reply_binding_present
        && terminal_chat_reply_binding_digest == sha256_prefixed(&obs.final_reply);
    let terminal_chat_reply_layout_profile =
        cec_receipt_value(obs, "postcondition", "terminal_chat_reply_layout_profile")
            .unwrap_or_default();
    let postcondition_terminal_output_shape_receipts_present = terminal_chat_reply_layout_profile
        == "single_snapshot"
        && has_cec_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_story_headers_absent",
            Some(true),
        )
        && has_cec_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_comparison_absent",
            Some(true),
        )
        && has_cec_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_temporal_anchor_floor",
            Some(true),
        )
        && has_cec_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_postamble_floor",
            Some(true),
        );
    let objective_specific_bitcoin_price_evidence_present = final_story_slots_observed >= 1
        && has_cec_receipt(obs, "verification", "story_citation_floor", Some(true))
        && has_cec_receipt(
            obs,
            "verification",
            "single_snapshot_metric_grounding",
            Some(true),
        )
        && final_output_contract_ready
        && single_snapshot_output_quality_receipts_present
        && postcondition_terminal_output_shape_receipts_present
        && postcondition_terminal_chat_reply_binding_present
        && terminal_chat_reply_binding_matches
        && final_story_citation_floor_met
        && final_single_snapshot_metric_grounding
        && selected_source_subject_alignment_receipts_present
        && (!final_comparison_required || final_comparison_ready);

    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_contract_gate_satisfied =
        cec_contract_gate_seen || (cec_execution_seen && cec_verification_seen);
    let contract_failure_markers_absent = !has_typed_contract_failure_evidence(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && obs.chat_reply_count > 0
        && cec_contract_gate_satisfied
        && final_output_contract_ready;

    let evidence_receipts = build_evidence_receipts(obs, currentness_required);
    let evidence_receipts_satisfied = evidence_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_bitcoin_price_evidence_present,
        tool_and_route_path_evidence_present,
        temporal_contract_receipts_present,
        source_floor_receipts_present,
        selected_source_quality_receipts_present,
        selected_source_subject_alignment_receipts_present,
        cec_contract_gate_satisfied,
        evidence_receipts_satisfied,
        contract_failure_markers_absent,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_bitcoin_price_evidence_present && independent_channel_count >= 8;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} cec_contract_gate_satisfied={} final_output_contract_ready={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                cec_contract_gate_satisfied,
                final_output_contract_ready
            ),
        ),
        LocalCheck::new(
            "objective_specific_bitcoin_price_evidence_present",
            objective_specific_bitcoin_price_evidence_present,
            format!(
                "final_story_slots_observed={} story_citation_floor_met={} final_single_snapshot_metric_grounding={} final_output_contract_ready={} single_snapshot_output_quality_receipts_present={} postcondition_terminal_output_shape_receipts_present={} terminal_chat_reply_binding_matches={} terminal_chat_reply_layout_profile={}",
                final_story_slots_observed,
                final_story_citation_floor_met,
                final_single_snapshot_metric_grounding,
                final_output_contract_ready,
                single_snapshot_output_quality_receipts_present,
                postcondition_terminal_output_shape_receipts_present,
                terminal_chat_reply_binding_matches,
                terminal_chat_reply_layout_profile
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "web_search_path_seen={} web_read_path_seen={} direct_fetch_path_seen={} action_tools={:?} routing_tools={:?} workload_tools={:?}",
                web_search_path_seen,
                web_read_path_seen,
                direct_fetch_path_seen,
                obs.action_tools,
                obs.routing_tools,
                obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "temporal_contract_receipts_present",
            temporal_contract_receipts_present,
            format!(
                "web_query_contract={} runtime_locality_required={} runtime_locality_satisfied={}",
                runtime_query_contract,
                runtime_locality_required,
                runtime_locality_satisfied
            ),
        ),
        LocalCheck::new(
            "source_floor_receipts_present",
            source_floor_receipts_present,
            format!(
                "web_min_sources={} web_sources_success={} verification_checks={:?}",
                web_min_sources, web_sources_success, obs.verification_checks
            ),
        ),
        LocalCheck::new(
            "selected_source_quality_receipts_present",
            selected_source_quality_receipts_present,
            format!(
                "quality_floor_receipt_met={} selected_source_count={} selected_source_distinct_domains={} required_independent_sources={} selected_source_urls={:?}",
                selected_source_quality_floor_met,
                selected_source_count,
                selected_source_distinct_domains,
                required_independent_sources,
                selected_source_urls
            ),
        ),
        LocalCheck::new(
            "selected_source_subject_alignment_receipts_present",
            selected_source_subject_alignment_receipts_present,
            format!(
                "selected_source_subject_alignment_floor_met={} selected_source_subject_alignment_urls={:?}",
                selected_source_subject_alignment_floor_met,
                web.selected_source_subject_alignment_urls
            ),
        ),
        LocalCheck::new(
            "cec_contract_gate_satisfied",
            cec_contract_gate_satisfied,
            format!(
                "execution={} verification={} completion_gate={} cec_receipts={:?}",
                cec_execution_seen, cec_verification_seen, cec_contract_gate_seen, obs.cec_receipts
            ),
        ),
        LocalCheck::new(
            "evidence_receipts_satisfied",
            evidence_receipts_satisfied,
            serialize_evidence_receipts(&evidence_receipts),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            contract_failure_markers_absent,
            truncate_chars(
                &format!(
                    "contract_failure_evidence_present={} verification_checks={:?} event_excerpt={:?}",
                    has_typed_contract_failure_evidence(obs),
                    obs.verification_checks,
                    obs.event_excerpt
                ),
                320,
            ),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_bitcoin_price_evidence_present={}",
                independent_channel_count,
                objective_specific_bitcoin_price_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

#[allow(clippy::too_many_arguments)]
fn build_evidence_receipts(
    obs: &RunObservation,
    currentness_required: bool,
) -> Vec<EvidenceReceipt> {
    vec![
        observed_receipt(
            obs,
            "execution",
            "query_contract",
            "bitcoin_runtime_query_contract_observed",
        ),
        observed_receipt(
            obs,
            "execution",
            "currentness_required",
            "bitcoin_currentness_contract_observed",
        ),
        observed_receipt(
            obs,
            "execution",
            "min_sources_required",
            "bitcoin_min_sources_contract_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "source_floor",
            "bitcoin_source_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "selected_source_quality_floor",
            "bitcoin_final_source_selection_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "selected_source_subject_alignment_floor",
            "bitcoin_selected_source_subject_alignment_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "single_snapshot_metric_grounding",
            "bitcoin_final_metric_grounding_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "final_output_contract_ready",
            "bitcoin_final_output_contract_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "single_snapshot_rendered_layout",
            "bitcoin_single_snapshot_layout_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "single_snapshot_metric_line_floor",
            "bitcoin_single_snapshot_metric_line_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "single_snapshot_support_url_floor",
            "bitcoin_single_snapshot_support_url_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "single_snapshot_read_backed_url_floor",
            "bitcoin_single_snapshot_read_backed_url_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "single_snapshot_temporal_signal",
            "bitcoin_single_snapshot_temporal_signal_observed",
        ),
        observed_receipt(
            obs,
            "completion_gate",
            "contract_gate",
            "bitcoin_completion_gate_observed",
        ),
        observed_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_layout_profile",
            "bitcoin_terminal_layout_profile_observed",
        ),
        observed_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_binding",
            "bitcoin_terminal_binding_observed",
        ),
        EvidenceReceipt {
            key: "bitcoin_currentness_contract_true".to_string(),
            observed_value: currentness_required.to_string(),
            probe_source: "RunObservation.web".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: currentness_required,
        },
    ]
}

fn observed_receipt(
    obs: &RunObservation,
    stage: &str,
    key: &str,
    logical_key: &str,
) -> EvidenceReceipt {
    if let Some(receipt) = obs.cec_receipts.iter().rev().find(|receipt| {
        receipt.stage.eq_ignore_ascii_case(stage) && receipt.key.eq_ignore_ascii_case(key)
    }) {
        return EvidenceReceipt {
            key: logical_key.to_string(),
            observed_value: receipt
                .observed_value
                .clone()
                .unwrap_or_else(|| "<missing>".to_string()),
            probe_source: receipt
                .probe_source
                .clone()
                .unwrap_or_else(|| "RunObservation.cec_receipts".to_string()),
            timestamp_ms: receipt.timestamp_ms,
            satisfied: receipt.satisfied,
        };
    }

    EvidenceReceipt {
        key: logical_key.to_string(),
        observed_value: "<missing>".to_string(),
        probe_source: "RunObservation.cec_receipts".to_string(),
        timestamp_ms: 0,
        satisfied: false,
    }
}

fn serialize_evidence_receipts(receipts: &[EvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}

fn sha256_prefixed(value: &str) -> String {
    sha256(value.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string())
}
