use ioi_crypto::algorithms::hash::sha256;
use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;

use super::super::types::{
    cec_receipt_value, environment_bool, environment_u64, environment_value, has_cec_receipt,
    has_cec_stage, has_typed_contract_failure_evidence, observation_has_tool_name, truncate_chars,
    ExecutionProfile, LocalCheck, LocalJudgeResult, QueryCase, RunObservation, WebObservation,
};

const CASE_ID: &str =
    "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing";
const UNSEEDED_CASE_ID: &str =
    "research_the_latest_nist_post_quantum_cryptography_standards_and_write_me_a_one_page_briefing_unseeded";
const EXPECTED_FIXTURE_MODE: &str = "latest_nist_pqc_briefing_fixture_v1";
const EXPECTED_FIXTURE_PROBE_SOURCE: &str = "harness.latest_nist_pqc_briefing_fixture";

#[derive(Debug, Clone, Serialize)]
struct EvidenceReceipt {
    key: String,
    observed_value: String,
    probe_source: String,
    timestamp_ms: u64,
    satisfied: bool,
}

#[derive(Debug, Clone, Serialize)]
struct EnvironmentEvidenceReceipt {
    key: &'static str,
    observed_value: String,
    probe_source: String,
    timestamp_ms: u64,
    satisfied: bool,
}

#[derive(Debug, Clone, Serialize)]
struct TerminalArtifactObservation {
    reply_sha256: String,
    char_count: usize,
    heading_present: bool,
    story_header_count: usize,
    comparison_label_count: usize,
    run_date_present: bool,
    run_timestamp_present: bool,
    overall_confidence_present: bool,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        success_definition: "Produce a sourced briefing on the latest NIST post-quantum cryptography standards with multi-standard retrieval planning, authoritative NIST source grounding, currentness + provider-selection receipts, and isolated current-date cleanup evidence.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        seed_resolved_intent: true,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 120,
        max_steps: 20,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

pub fn case_unseeded() -> QueryCase {
    QueryCase {
        id: UNSEEDED_CASE_ID,
        query: "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
        success_definition: "Resolve and produce a sourced briefing on the latest NIST post-quantum cryptography standards without a seeded intent override, with authoritative NIST source grounding, currentness + provider-selection receipts, and isolated current-date cleanup evidence.",
        seeded_intent_id: "web.research",
        intent_scope: IntentScopeProfile::WebResearch,
        seed_resolved_intent: false,
        expected_pass: true,
        execution_profile: ExecutionProfile::Hermetic,
        sla_seconds: 120,
        max_steps: 20,
        min_local_score: 1.0,
        allow_retry_blocked_completion_with_local_evidence: false,
        allow_timeout_completion_with_local_evidence: false,
        local_sniff: evaluate,
    }
}

fn benchmark_briefing_standard_inventory_quality_met(
    floor_met: bool,
    group_floor: usize,
    required_count: usize,
    total_count: usize,
    authority_source_count: usize,
    available_authority_source_count: usize,
) -> bool {
    floor_met
        && (group_floor == 0
            || (required_count >= group_floor
                && total_count >= required_count
                && (available_authority_source_count == 0 || authority_source_count >= 1)))
}

fn benchmark_briefing_authority_standard_inventory_quality_met(
    floor_met: bool,
    group_floor: usize,
    required_authority_count: usize,
    authority_total_count: usize,
) -> bool {
    floor_met
        && (group_floor == 0
            || (required_authority_count >= group_floor
                && authority_total_count >= required_authority_count))
}

fn benchmark_briefing_summary_inventory_quality_met(
    floor_met: bool,
    group_floor: usize,
    required_count: usize,
    optional_count: usize,
    authority_count: usize,
    available_authority_source_count: usize,
    required_authority_count: usize,
) -> bool {
    let authority_only_optional_floor_met = required_count == 0
        && optional_count > group_floor
        && authority_count == optional_count
        && required_authority_count >= group_floor;
    floor_met
        && (group_floor == 0
            || (required_count >= group_floor
                && optional_count == 0
                && (available_authority_source_count == 0 || authority_count >= group_floor))
            || authority_only_optional_floor_met)
}

fn benchmark_selected_source_identifier_coverage_quality_met(
    floor_met: bool,
    identifier_evidence_required: bool,
    identifier_bearing_sources: usize,
    authority_identifier_sources: usize,
    required_identifier_label_coverage: usize,
    required_identifier_group_floor: usize,
    source_independence_min: usize,
) -> bool {
    floor_met
        && (!identifier_evidence_required
            || (identifier_bearing_sources >= source_independence_min.max(1)
                && required_identifier_label_coverage >= required_identifier_group_floor
                && authority_identifier_sources >= 1))
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

    let retrieval_contract = web.retrieval_contract.as_ref();
    let entity_cardinality_min = retrieval_contract
        .map(|contract| contract.entity_cardinality_min as usize)
        .unwrap_or(0);
    let source_independence_min = retrieval_contract
        .map(|contract| contract.source_independence_min as usize)
        .unwrap_or_else(|| web.min_sources.unwrap_or(0));
    let currentness_required = retrieval_contract
        .map(|contract| contract.currentness_required)
        .unwrap_or_else(|| web.currentness_required.unwrap_or(false));
    let discovery_surface_required = retrieval_contract
        .map(|contract| contract.discovery_surface_required)
        .unwrap_or(false);
    let comparison_required = retrieval_contract
        .map(|contract| contract.comparison_required)
        .unwrap_or(false);
    let browser_fallback_allowed = retrieval_contract
        .map(|contract| contract.browser_fallback_allowed)
        .unwrap_or(true);

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
    let provider_discovery_evidence_present =
        provider_candidate_count > 0 && provider_success_count > 0 && provider_selected_count > 0;

    let runtime_query_contract = web.query_contract.clone().unwrap_or_default();
    let semantic_subject_alignment_required =
        web.semantic_subject_alignment_required.unwrap_or(false);
    let semantic_subject_alignment_receipts_present = if !semantic_subject_alignment_required {
        true
    } else {
        has_cec_receipt(
            obs,
            "discovery",
            "semantic_subject_alignment_required",
            Some(true),
        ) && web.semantic_subject_alignment_floor_met.unwrap_or(false)
            && web
                .selected_source_subject_alignment_floor_met
                .unwrap_or(false)
            && !web.semantic_subject_alignment_urls.is_empty()
    };

    let selected_source_count = web
        .selected_source_count
        .unwrap_or_else(|| web.selected_source_urls.len());
    let selected_source_quality_floor_met = web.selected_source_quality_floor_met.unwrap_or(false);
    let source_floor_receipts_present =
        has_cec_receipt(obs, "verification", "source_floor", Some(true))
            && web.source_floor_met.unwrap_or(false)
            && web.sources_success.unwrap_or(0) >= source_independence_min.max(1);
    let selected_source_quality_receipts_present = has_cec_receipt(
        obs,
        "verification",
        "selected_source_quality_floor",
        Some(true),
    ) && selected_source_quality_floor_met
        && selected_source_count >= source_independence_min.max(1);
    let selected_source_identifier_coverage_summary = cec_receipt_value(
        obs,
        "verification",
        "selected_source_identifier_coverage_floor",
    )
    .unwrap_or_default();
    let selected_source_identifier_coverage_floor_met = has_cec_receipt(
        obs,
        "verification",
        "selected_source_identifier_coverage_floor",
        Some(true),
    );
    let selected_source_identifier_evidence_required = summary_bool_field(
        &selected_source_identifier_coverage_summary,
        "identifier_evidence_required",
    )
    .unwrap_or(false);
    let selected_source_identifier_bearing_sources = summary_usize_field(
        &selected_source_identifier_coverage_summary,
        "identifier_bearing_sources",
    )
    .unwrap_or(0);
    let selected_source_authority_identifier_sources = summary_usize_field(
        &selected_source_identifier_coverage_summary,
        "authority_identifier_sources",
    )
    .unwrap_or(0);
    let selected_source_required_identifier_label_coverage = summary_usize_field(
        &selected_source_identifier_coverage_summary,
        "required_identifier_label_coverage",
    )
    .unwrap_or(0);
    let selected_source_optional_identifier_label_coverage = summary_usize_field(
        &selected_source_identifier_coverage_summary,
        "optional_identifier_label_coverage",
    )
    .unwrap_or(0);
    let selected_source_required_identifier_group_floor = summary_usize_field(
        &selected_source_identifier_coverage_summary,
        "required_identifier_group_floor",
    )
    .unwrap_or(0);
    let selected_source_identifier_coverage_receipts_present =
        benchmark_selected_source_identifier_coverage_quality_met(
            selected_source_identifier_coverage_floor_met,
            selected_source_identifier_evidence_required,
            selected_source_identifier_bearing_sources,
            selected_source_authority_identifier_sources,
            selected_source_required_identifier_label_coverage,
            selected_source_required_identifier_group_floor,
            source_independence_min,
        );

    let selected_official_nist_source_count = official_nist_source_count(&web.selected_source_urls);
    let selected_aligned_official_nist_source_count =
        official_nist_source_count(&web.selected_source_subject_alignment_urls);
    let discovery_semantic_official_nist_alignment_count =
        official_nist_source_count(&web.semantic_subject_alignment_urls);
    let official_nist_source_evidence_present =
        official_nist_selected_alignment_evidence_present(web);

    let briefing_document_layout_met =
        has_cec_receipt(obs, "verification", "briefing_document_layout", Some(true));
    let briefing_render_heading_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_render_heading_floor",
        Some(true),
    );
    let briefing_rendered_required_section_label_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_rendered_required_section_label_floor",
        Some(true),
    );
    let briefing_story_headers_absent = has_cec_receipt(
        obs,
        "verification",
        "briefing_story_headers_absent",
        Some(true),
    );
    let briefing_comparison_absent = has_cec_receipt(
        obs,
        "verification",
        "briefing_comparison_absent",
        Some(true),
    );
    let briefing_required_section_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_required_section_floor",
        Some(true),
    );
    let briefing_query_grounding_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_query_grounding_floor",
        Some(true),
    );
    let briefing_standard_identifier_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_standard_identifier_floor",
        Some(true),
    );
    let briefing_authority_standard_identifier_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_authority_standard_identifier_floor",
        Some(true),
    );
    let briefing_summary_inventory_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_summary_inventory_floor",
        Some(true),
    );
    let briefing_narrative_aggregation_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_narrative_aggregation_floor",
        Some(true),
    );
    let briefing_evidence_block_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_evidence_block_floor",
        Some(true),
    );
    let briefing_primary_authority_source_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_primary_authority_source_floor",
        Some(true),
    );
    let briefing_citation_read_backing_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_citation_read_backing_floor",
        Some(true),
    );
    let briefing_temporal_anchor_floor_met = has_cec_receipt(
        obs,
        "verification",
        "briefing_temporal_anchor_floor",
        Some(true),
    );
    let briefing_postamble_floor_met =
        has_cec_receipt(obs, "verification", "briefing_postamble_floor", Some(true));
    let briefing_standard_identifier_summary =
        cec_receipt_value(obs, "verification", "briefing_standard_identifier_floor")
            .unwrap_or_default();
    let briefing_authority_standard_identifier_summary = cec_receipt_value(
        obs,
        "verification",
        "briefing_authority_standard_identifier_floor",
    )
    .unwrap_or_default();
    let briefing_summary_inventory_summary =
        cec_receipt_value(obs, "verification", "briefing_summary_inventory_floor")
            .unwrap_or_default();
    let briefing_evidence_block_summary =
        cec_receipt_value(obs, "verification", "briefing_evidence_block_floor").unwrap_or_default();
    let briefing_citation_read_backing_summary =
        cec_receipt_value(obs, "verification", "briefing_citation_read_backing_floor")
            .unwrap_or_default();
    let briefing_standard_identifier_count = summary_usize_field(
        &briefing_standard_identifier_summary,
        "standard_identifier_count",
    )
    .unwrap_or(0);
    let briefing_required_standard_identifier_count = summary_usize_field(
        &briefing_standard_identifier_summary,
        "required_standard_identifier_count",
    )
    .unwrap_or(0);
    let briefing_standard_identifier_group_floor = summary_usize_field(
        &briefing_standard_identifier_summary,
        "required_standard_identifier_group_floor",
    )
    .unwrap_or(0);
    let briefing_standard_identifier_authority_source_count = summary_usize_field(
        &briefing_standard_identifier_summary,
        "standard_identifier_authority_source_count",
    )
    .unwrap_or(0);
    let briefing_available_standard_identifier_authority_source_count = summary_usize_field(
        &briefing_standard_identifier_summary,
        "available_standard_identifier_authority_source_count",
    )
    .unwrap_or(0);
    let briefing_authority_standard_identifier_count = summary_usize_field(
        &briefing_authority_standard_identifier_summary,
        "authority_standard_identifier_count",
    )
    .unwrap_or(0);
    let briefing_required_authority_standard_identifier_count = summary_usize_field(
        &briefing_authority_standard_identifier_summary,
        "required_authority_standard_identifier_count",
    )
    .unwrap_or(0);
    let briefing_standard_inventory_quality_met = benchmark_briefing_standard_inventory_quality_met(
        briefing_standard_identifier_floor_met,
        briefing_standard_identifier_group_floor,
        briefing_required_standard_identifier_count,
        briefing_standard_identifier_count,
        briefing_standard_identifier_authority_source_count,
        briefing_available_standard_identifier_authority_source_count,
    );
    let briefing_authority_standard_inventory_quality_met =
        benchmark_briefing_authority_standard_inventory_quality_met(
            briefing_authority_standard_identifier_floor_met,
            briefing_standard_identifier_group_floor,
            briefing_required_authority_standard_identifier_count,
            briefing_authority_standard_identifier_count,
        );
    let briefing_summary_inventory_identifier_count = summary_usize_field(
        &briefing_summary_inventory_summary,
        "summary_inventory_identifier_count",
    )
    .unwrap_or(0);
    let briefing_summary_inventory_required_identifier_count = summary_usize_field(
        &briefing_summary_inventory_summary,
        "summary_inventory_required_identifier_count",
    )
    .unwrap_or(0);
    let briefing_summary_inventory_optional_identifier_count = summary_usize_field(
        &briefing_summary_inventory_summary,
        "summary_inventory_optional_identifier_count",
    )
    .unwrap_or(usize::MAX);
    let briefing_summary_inventory_authority_identifier_count = summary_usize_field(
        &briefing_summary_inventory_summary,
        "summary_inventory_authority_identifier_count",
    )
    .unwrap_or(0);
    let briefing_summary_inventory_quality_met = benchmark_briefing_summary_inventory_quality_met(
        briefing_summary_inventory_floor_met,
        briefing_standard_identifier_group_floor,
        briefing_summary_inventory_required_identifier_count,
        briefing_summary_inventory_optional_identifier_count,
        briefing_summary_inventory_authority_identifier_count,
        briefing_available_standard_identifier_authority_source_count,
        briefing_required_authority_standard_identifier_count,
    );
    let briefing_rendered_evidence_block_count = summary_usize_field(
        &briefing_evidence_block_summary,
        "rendered_evidence_block_count",
    )
    .unwrap_or(0);
    let briefing_required_evidence_sections = summary_usize_field(
        &briefing_evidence_block_summary,
        "required_evidence_sections",
    )
    .unwrap_or(0);
    let briefing_qualifying_evidence_sections = summary_usize_field(
        &briefing_evidence_block_summary,
        "qualifying_evidence_sections",
    )
    .unwrap_or(0);
    let briefing_successful_citation_url_count = summary_usize_field(
        &briefing_citation_read_backing_summary,
        "successful_citation_url_count",
    )
    .unwrap_or(0);
    let briefing_unread_citation_url_count = summary_usize_field(
        &briefing_citation_read_backing_summary,
        "unread_citation_url_count",
    )
    .unwrap_or(usize::MAX);
    let briefing_required_supporting_fragment_floor = summary_usize_field(
        &briefing_citation_read_backing_summary,
        "required_supporting_fragment_floor",
    )
    .unwrap_or(0);
    let briefing_citation_provenance_quality_met = briefing_citation_read_backing_floor_met
        && briefing_unread_citation_url_count == 0
        && briefing_successful_citation_url_count
            >= briefing_required_supporting_fragment_floor.max(1);
    let briefing_evidence_block_quality_met = briefing_evidence_block_floor_met
        && briefing_required_supporting_fragment_floor >= 2
        && briefing_rendered_evidence_block_count
            >= briefing_required_supporting_fragment_floor.max(briefing_required_evidence_sections)
        && briefing_qualifying_evidence_sections >= briefing_required_evidence_sections.max(1);
    let briefing_story_slot_receipts_absent =
        !has_cec_receipt(obs, "verification", "story_slots_observed", None)
            && !has_cec_receipt(obs, "verification", "story_slot_floor", None)
            && !has_cec_receipt(obs, "verification", "story_citation_floor", None);
    let briefing_document_layout_summary =
        cec_receipt_value(obs, "verification", "briefing_document_layout").unwrap_or_default();
    let briefing_story_headers_summary =
        cec_receipt_value(obs, "verification", "briefing_story_headers_absent").unwrap_or_default();
    let briefing_comparison_summary =
        cec_receipt_value(obs, "verification", "briefing_comparison_absent").unwrap_or_default();
    let briefing_query_layout_expected_receipt = summary_bool_field(
        &briefing_document_layout_summary,
        "query_requires_document_briefing",
    )
    .unwrap_or(false);
    let briefing_contract_layout_profile =
        summary_string_field(&briefing_document_layout_summary, "contract_layout")
            .unwrap_or_default();
    let briefing_rendered_layout_profile =
        summary_string_field(&briefing_document_layout_summary, "rendered_layout")
            .unwrap_or_default();
    let briefing_story_header_count =
        summary_usize_field(&briefing_story_headers_summary, "story_header_count")
            .unwrap_or(usize::MAX);
    let briefing_comparison_label_count =
        summary_usize_field(&briefing_comparison_summary, "comparison_label_count")
            .unwrap_or(usize::MAX);
    let final_output_contract_ready = has_cec_receipt(
        obs,
        "verification",
        "final_output_contract_ready",
        Some(true),
    );
    let terminal_artifact = observe_terminal_artifact(&obs.final_reply);
    let terminal_chat_reply_binding_digest =
        cec_receipt_value(obs, "postcondition", "terminal_chat_reply_binding").unwrap_or_default();
    let postcondition_terminal_chat_reply_binding_present =
        has_cec_stage(obs, "postcondition", Some(true))
            && has_cec_receipt(
                obs,
                "postcondition",
                "terminal_chat_reply_binding",
                Some(true),
            );
    let terminal_chat_reply_binding_matches = postcondition_terminal_chat_reply_binding_present
        && terminal_chat_reply_binding_digest == terminal_artifact.reply_sha256;
    let postcondition_terminal_layout_profile =
        cec_receipt_value(obs, "postcondition", "terminal_chat_reply_layout_profile")
            .unwrap_or_default();
    let postcondition_story_headers_absent = has_cec_receipt(
        obs,
        "postcondition",
        "terminal_chat_reply_story_headers_absent",
        Some(true),
    );
    let postcondition_comparison_absent = has_cec_receipt(
        obs,
        "postcondition",
        "terminal_chat_reply_comparison_absent",
        Some(true),
    );
    let postcondition_temporal_anchor_floor = has_cec_receipt(
        obs,
        "postcondition",
        "terminal_chat_reply_temporal_anchor_floor",
        Some(true),
    );
    let postcondition_postamble_floor = has_cec_receipt(
        obs,
        "postcondition",
        "terminal_chat_reply_postamble_floor",
        Some(true),
    );
    let postcondition_terminal_output_shape_receipts_present = postcondition_terminal_layout_profile
        == "document_briefing"
        && postcondition_story_headers_absent
        && postcondition_comparison_absent
        && postcondition_temporal_anchor_floor
        && postcondition_postamble_floor;
    let terminal_output_document_briefing_shape_met = terminal_artifact.heading_present
        && terminal_artifact.story_header_count == 0
        && terminal_artifact.comparison_label_count == 0
        && terminal_artifact.run_date_present
        && terminal_artifact.run_timestamp_present
        && terminal_artifact.overall_confidence_present;
    let rendered_output_quality_receipts_present = final_output_contract_ready
        && !browser_fallback_allowed
        && postcondition_terminal_chat_reply_binding_present
        && terminal_chat_reply_binding_matches
        && postcondition_terminal_output_shape_receipts_present
        && terminal_output_document_briefing_shape_met
        && briefing_query_layout_expected_receipt
        && briefing_contract_layout_profile == "document_briefing"
        && briefing_rendered_layout_profile == "document_briefing"
        && briefing_story_header_count == 0
        && briefing_comparison_label_count == 0;

    let retrieval_contract_document_briefing_present = entity_cardinality_min == 1
        && source_independence_min >= 2
        && currentness_required
        && discovery_surface_required
        && !comparison_required;
    let objective_specific_briefing_evidence_present = retrieval_contract_document_briefing_present
        && rendered_output_quality_receipts_present
        && briefing_document_layout_met
        && briefing_render_heading_floor_met
        && briefing_rendered_required_section_label_floor_met
        && briefing_story_headers_absent
        && briefing_comparison_absent
        && briefing_story_slot_receipts_absent
        && briefing_required_section_floor_met
        && briefing_query_grounding_floor_met
        && briefing_standard_inventory_quality_met
        && briefing_authority_standard_inventory_quality_met
        && briefing_summary_inventory_quality_met
        && briefing_narrative_aggregation_floor_met
        && briefing_evidence_block_quality_met
        && briefing_primary_authority_source_floor_met
        && briefing_citation_provenance_quality_met
        && briefing_temporal_anchor_floor_met
        && briefing_postamble_floor_met
        && selected_source_identifier_coverage_receipts_present
        && selected_official_nist_source_count >= 1
        && official_nist_source_evidence_present;

    let tool_and_route_path_evidence_present = observation_has_tool_name(obs, "web__search")
        && observation_has_tool_name(obs, "web__read")
        && !observation_has_tool_name(obs, "http__fetch");
    let cec_required_phase_receipts_present = has_cec_stage(obs, "discovery", Some(true))
        && has_cec_stage(obs, "provider_selection", Some(true))
        && has_cec_stage(obs, "execution", Some(true))
        && has_cec_stage(obs, "verification", Some(true))
        && has_cec_stage(obs, "postcondition", Some(true))
        && has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let contract_failure_markers_absent = !has_typed_contract_failure_evidence(obs);
    let completion_evidence_present = obs.completed
        && !obs.failed
        && obs.chat_reply_count > 0
        && has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));

    let evidence_receipts = build_evidence_receipts(obs, currentness_required);
    let evidence_receipts_satisfied = evidence_receipts.iter().all(|receipt| receipt.satisfied);

    let environment_receipts = collect_environment_receipts(obs);
    let fixture_mode_matches =
        environment_value(obs, "env_receipt::latest_nist_pqc_briefing_fixture_mode")
            .is_some_and(|value| value == EXPECTED_FIXTURE_MODE);
    let environment_receipts_satisfied =
        fixture_mode_matches && environment_receipts.iter().all(|receipt| receipt.satisfied);
    let cleanup_evidence_present = environment_bool(
        obs,
        "env_receipt::latest_nist_pqc_briefing_cleanup_satisfied",
    )
    .unwrap_or(false);

    let independent_channel_count = [
        completion_evidence_present,
        provider_discovery_evidence_present,
        objective_specific_briefing_evidence_present,
        rendered_output_quality_receipts_present,
        postcondition_terminal_chat_reply_binding_present,
        postcondition_terminal_output_shape_receipts_present,
        terminal_output_document_briefing_shape_met,
        briefing_summary_inventory_quality_met,
        briefing_evidence_block_quality_met,
        briefing_citation_provenance_quality_met,
        tool_and_route_path_evidence_present,
        source_floor_receipts_present,
        selected_source_quality_receipts_present,
        selected_source_identifier_coverage_receipts_present,
        semantic_subject_alignment_receipts_present,
        cec_required_phase_receipts_present,
        evidence_receipts_satisfied,
        environment_receipts_satisfied,
        cleanup_evidence_present,
        contract_failure_markers_absent,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_briefing_evidence_present && independent_channel_count >= 10;
    let requires_live_intent_resolution = obs.case_id.eq_ignore_ascii_case(UNSEEDED_CASE_ID);
    let latest_intent_resolution = obs.intent_resolution_evidence.last();
    let intent_resolution_routes_to_web_research = !requires_live_intent_resolution
        || latest_intent_resolution
            .map(|receipt| {
                receipt.intent_id.eq_ignore_ascii_case("web.research")
                    && receipt.error_class.is_none()
            })
            .unwrap_or(false);

    let checks = vec![
        LocalCheck::new(
            "intent_resolution_routes_to_web_research",
            intent_resolution_routes_to_web_research,
            format!(
                "requires_live_intent_resolution={} intent_resolution_evidence={:?}",
                requires_live_intent_resolution, obs.intent_resolution_evidence
            ),
        ),
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={}",
                obs.final_status, obs.completed, obs.failed, obs.chat_reply_count
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
            "objective_specific_briefing_evidence_present",
            objective_specific_briefing_evidence_present,
            format!(
                "entity_cardinality_min={} source_independence_min={} comparison_required={} browser_fallback_allowed={} rendered_output_quality_receipts_present={} postcondition_terminal_chat_reply_binding_present={} terminal_chat_reply_binding_matches={} postcondition_terminal_output_shape_receipts_present={} terminal_output_document_briefing_shape_met={} postcondition_terminal_layout_profile={} briefing_document_layout_met={} briefing_render_heading_floor_met={} briefing_rendered_required_section_label_floor_met={} briefing_story_headers_absent={} briefing_comparison_absent={} briefing_story_slot_receipts_absent={} briefing_required_section_floor_met={} briefing_query_grounding_floor_met={} briefing_standard_identifier_floor_met={} briefing_authority_standard_identifier_floor_met={} briefing_standard_inventory_quality_met={} briefing_authority_standard_inventory_quality_met={} briefing_summary_inventory_quality_met={} briefing_evidence_block_quality_met={} briefing_citation_provenance_quality_met={} briefing_standard_identifier_count={} briefing_required_standard_identifier_count={} briefing_standard_identifier_group_floor={} briefing_authority_standard_identifier_count={} briefing_required_authority_standard_identifier_count={} briefing_summary_inventory_identifier_count={} briefing_summary_inventory_required_identifier_count={} briefing_summary_inventory_optional_identifier_count={} briefing_summary_inventory_authority_identifier_count={} briefing_standard_identifier_authority_source_count={} briefing_available_standard_identifier_authority_source_count={} briefing_rendered_evidence_block_count={} briefing_required_evidence_sections={} briefing_qualifying_evidence_sections={} briefing_successful_citation_url_count={} briefing_unread_citation_url_count={} briefing_required_supporting_fragment_floor={} briefing_narrative_aggregation_floor_met={} briefing_primary_authority_source_floor_met={} briefing_temporal_anchor_floor_met={} briefing_postamble_floor_met={} selected_official_nist_source_count={} selected_aligned_official_nist_source_count={} discovery_semantic_official_nist_alignment_count={}",
                entity_cardinality_min,
                source_independence_min,
                comparison_required,
                browser_fallback_allowed,
                rendered_output_quality_receipts_present,
                postcondition_terminal_chat_reply_binding_present,
                terminal_chat_reply_binding_matches,
                postcondition_terminal_output_shape_receipts_present,
                terminal_output_document_briefing_shape_met,
                postcondition_terminal_layout_profile,
                briefing_document_layout_met,
                briefing_render_heading_floor_met,
                briefing_rendered_required_section_label_floor_met,
                briefing_story_headers_absent,
                briefing_comparison_absent,
                briefing_story_slot_receipts_absent,
                briefing_required_section_floor_met,
                briefing_query_grounding_floor_met,
                briefing_standard_identifier_floor_met,
                briefing_authority_standard_identifier_floor_met,
                briefing_standard_inventory_quality_met,
                briefing_authority_standard_inventory_quality_met,
                briefing_summary_inventory_quality_met,
                briefing_evidence_block_quality_met,
                briefing_citation_provenance_quality_met,
                briefing_standard_identifier_count,
                briefing_required_standard_identifier_count,
                briefing_standard_identifier_group_floor,
                briefing_authority_standard_identifier_count,
                briefing_required_authority_standard_identifier_count,
                briefing_summary_inventory_identifier_count,
                briefing_summary_inventory_required_identifier_count,
                briefing_summary_inventory_optional_identifier_count,
                briefing_summary_inventory_authority_identifier_count,
                briefing_standard_identifier_authority_source_count,
                briefing_available_standard_identifier_authority_source_count,
                briefing_rendered_evidence_block_count,
                briefing_required_evidence_sections,
                briefing_qualifying_evidence_sections,
                briefing_successful_citation_url_count,
                briefing_unread_citation_url_count,
                briefing_required_supporting_fragment_floor,
                briefing_narrative_aggregation_floor_met,
                briefing_primary_authority_source_floor_met,
                briefing_temporal_anchor_floor_met,
                briefing_postamble_floor_met,
                selected_official_nist_source_count,
                selected_aligned_official_nist_source_count,
                discovery_semantic_official_nist_alignment_count
            ),
        ),
        LocalCheck::new(
            "rendered_output_quality_receipts_present",
            rendered_output_quality_receipts_present,
            format!(
                "final_output_contract_ready={} browser_fallback_allowed={} postcondition_terminal_chat_reply_binding_present={} terminal_chat_reply_binding_matches={} postcondition_terminal_output_shape_receipts_present={} postcondition_terminal_layout_profile={} query_requires_document_briefing={} contract_layout={} rendered_layout={} story_header_count={} comparison_label_count={}",
                final_output_contract_ready,
                browser_fallback_allowed,
                postcondition_terminal_chat_reply_binding_present,
                terminal_chat_reply_binding_matches,
                postcondition_terminal_output_shape_receipts_present,
                postcondition_terminal_layout_profile,
                briefing_query_layout_expected_receipt,
                briefing_contract_layout_profile,
                briefing_rendered_layout_profile,
                briefing_story_header_count,
                briefing_comparison_label_count
            ),
        ),
        LocalCheck::new(
            "postcondition_terminal_chat_reply_binding_present",
            postcondition_terminal_chat_reply_binding_present,
            format!(
                "reply_sha256={} receipt_observed_value={} final_reply_excerpt={}",
                terminal_artifact.reply_sha256,
                terminal_chat_reply_binding_digest,
                truncate_chars(&obs.final_reply, 220)
            ),
        ),
        LocalCheck::new(
            "terminal_output_document_briefing_shape_met",
            terminal_output_document_briefing_shape_met,
            serde_json::to_string(&terminal_artifact)
                .unwrap_or_else(|_| "{\"error\":\"serialize\"}".to_string()),
        ),
        LocalCheck::new(
            "postcondition_terminal_output_shape_receipts_present",
            postcondition_terminal_output_shape_receipts_present,
            format!(
                "layout_profile={} story_headers_absent={} comparison_absent={} temporal_anchor_floor={} postamble_floor={}",
                postcondition_terminal_layout_profile,
                postcondition_story_headers_absent,
                postcondition_comparison_absent,
                postcondition_temporal_anchor_floor,
                postcondition_postamble_floor
            ),
        ),
        LocalCheck::new(
            "briefing_summary_inventory_quality_met",
            briefing_summary_inventory_quality_met,
            format!(
                "briefing_summary_inventory_floor_met={} summary_inventory_identifier_count={} summary_inventory_required_identifier_count={} summary_inventory_optional_identifier_count={} summary_inventory_authority_identifier_count={} briefing_standard_identifier_group_floor={} briefing_available_standard_identifier_authority_source_count={}",
                briefing_summary_inventory_floor_met,
                briefing_summary_inventory_identifier_count,
                briefing_summary_inventory_required_identifier_count,
                briefing_summary_inventory_optional_identifier_count,
                briefing_summary_inventory_authority_identifier_count,
                briefing_standard_identifier_group_floor,
                briefing_available_standard_identifier_authority_source_count
            ),
        ),
        LocalCheck::new(
            "briefing_evidence_block_quality_met",
            briefing_evidence_block_quality_met,
            format!(
                "briefing_evidence_block_floor_met={} briefing_rendered_evidence_block_count={} briefing_required_evidence_sections={} briefing_qualifying_evidence_sections={} briefing_required_supporting_fragment_floor={}",
                briefing_evidence_block_floor_met,
                briefing_rendered_evidence_block_count,
                briefing_required_evidence_sections,
                briefing_qualifying_evidence_sections,
                briefing_required_supporting_fragment_floor
            ),
        ),
        LocalCheck::new(
            "briefing_citation_provenance_quality_met",
            briefing_citation_provenance_quality_met,
            format!(
                "briefing_citation_read_backing_floor_met={} successful_citation_url_count={} unread_citation_url_count={} required_supporting_fragment_floor={}",
                briefing_citation_read_backing_floor_met,
                briefing_successful_citation_url_count,
                briefing_unread_citation_url_count,
                briefing_required_supporting_fragment_floor
            ),
        ),
        LocalCheck::new(
            "tool_and_route_path_evidence_present",
            tool_and_route_path_evidence_present,
            format!(
                "action_tools={:?} routing_tools={:?} workload_tools={:?}",
                obs.action_tools, obs.routing_tools, obs.workload_tools
            ),
        ),
        LocalCheck::new(
            "source_floor_receipts_present",
            source_floor_receipts_present,
            format!(
                "source_independence_min={} sources_success={} source_floor_met={}",
                source_independence_min,
                web.sources_success.unwrap_or(0),
                web.source_floor_met.unwrap_or(false)
            ),
        ),
        LocalCheck::new(
            "selected_source_quality_receipts_present",
            selected_source_quality_receipts_present,
            format!(
                "selected_source_count={} selected_source_quality_floor_met={} selected_source_urls={:?}",
                selected_source_count, selected_source_quality_floor_met, web.selected_source_urls
            ),
        ),
        LocalCheck::new(
            "selected_source_identifier_coverage_receipts_present",
            selected_source_identifier_coverage_receipts_present,
            format!(
                "selected_source_identifier_evidence_required={} selected_source_identifier_coverage_floor_met={} selected_source_identifier_bearing_sources={} selected_source_authority_identifier_sources={} selected_source_required_identifier_label_coverage={} selected_source_optional_identifier_label_coverage={} selected_source_required_identifier_group_floor={}",
                selected_source_identifier_evidence_required,
                selected_source_identifier_coverage_floor_met,
                selected_source_identifier_bearing_sources,
                selected_source_authority_identifier_sources,
                selected_source_required_identifier_label_coverage,
                selected_source_optional_identifier_label_coverage,
                selected_source_required_identifier_group_floor
            ),
        ),
        LocalCheck::new(
            "semantic_subject_alignment_receipts_present",
            semantic_subject_alignment_receipts_present,
            format!(
                "required={} selected_source_subject_alignment_floor_met={} semantic_urls={:?} query_contract={}",
                semantic_subject_alignment_required,
                web.selected_source_subject_alignment_floor_met
                    .unwrap_or(false),
                web.semantic_subject_alignment_urls,
                truncate_chars(&runtime_query_contract, 180)
            ),
        ),
        LocalCheck::new(
            "cec_required_phase_receipts_present",
            cec_required_phase_receipts_present,
            format!("cec_receipts={:?}", obs.cec_receipts),
        ),
        LocalCheck::new(
            "evidence_receipts_satisfied",
            evidence_receipts_satisfied,
            serialize_evidence_receipts(&evidence_receipts),
        ),
        LocalCheck::new(
            "environment_receipts_satisfied",
            environment_receipts_satisfied,
            serialize_environment_receipts(&environment_receipts),
        ),
        LocalCheck::new(
            "cleanup_evidence_present",
            cleanup_evidence_present,
            format!(
                "cleanup={} cleanup_root_exists={} cleanup_manifest_exists={}",
                environment_bool(obs, "env_receipt::latest_nist_pqc_briefing_cleanup_satisfied")
                    .unwrap_or(false),
                environment_value(
                    obs,
                    "env_receipt::latest_nist_pqc_briefing_cleanup_root_exists"
                )
                .unwrap_or_default(),
                environment_value(
                    obs,
                    "env_receipt::latest_nist_pqc_briefing_cleanup_manifest_exists"
                )
                .unwrap_or_default(),
            ),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            contract_failure_markers_absent,
            truncate_chars(
                &format!(
                    "contract_failure_evidence_present={} action_error_classes={:?} routing_failure_classes={:?}",
                    has_typed_contract_failure_evidence(obs),
                    obs.action_error_classes,
                    obs.routing_failure_classes
                ),
                220,
            ),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!("independent_channel_count={}", independent_channel_count),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

fn is_official_nist_source(url: &str) -> bool {
    let normalized = url.trim().to_ascii_lowercase();
    normalized.contains("://nist.gov/")
        || normalized.contains("://www.nist.gov/")
        || normalized.contains("://csrc.nist.gov/")
        || normalized.contains("://nccoe.nist.gov/")
        || normalized.contains("://www.nccoe.nist.gov/")
        || normalized.contains("://nvlpubs.nist.gov/")
}

fn official_nist_source_count(urls: &[String]) -> usize {
    urls.iter()
        .filter(|url| is_official_nist_source(url))
        .count()
}

fn official_nist_selected_alignment_evidence_present(web: &WebObservation) -> bool {
    official_nist_source_count(&web.selected_source_urls) >= 1
        && official_nist_source_count(&web.selected_source_subject_alignment_urls) >= 1
        && web
            .selected_source_subject_alignment_floor_met
            .unwrap_or(false)
}

fn build_evidence_receipts(
    obs: &RunObservation,
    currentness_required: bool,
) -> Vec<EvidenceReceipt> {
    vec![
        observed_receipt(
            obs,
            "execution",
            "query_contract",
            "nist_pqc_query_contract_observed",
        ),
        observed_receipt(
            obs,
            "execution",
            "retrieval_contract",
            "nist_pqc_retrieval_contract_observed",
        ),
        observed_receipt(
            obs,
            "execution",
            "currentness_required",
            "nist_pqc_currentness_required_observed",
        ),
        observed_receipt(
            obs,
            "provider_selection",
            "provider_selected",
            "nist_pqc_provider_selection_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "source_floor",
            "nist_pqc_source_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "selected_source_quality_floor",
            "nist_pqc_selected_source_quality_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "final_output_contract_ready",
            "nist_pqc_final_output_contract_ready_observed",
        ),
        observed_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_binding",
            "nist_pqc_terminal_chat_reply_binding_observed",
        ),
        observed_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_layout_profile",
            "nist_pqc_terminal_chat_reply_layout_profile_observed",
        ),
        observed_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_story_headers_absent",
            "nist_pqc_terminal_chat_reply_story_headers_absent_observed",
        ),
        observed_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_comparison_absent",
            "nist_pqc_terminal_chat_reply_comparison_absent_observed",
        ),
        observed_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_temporal_anchor_floor",
            "nist_pqc_terminal_chat_reply_temporal_anchor_floor_observed",
        ),
        observed_receipt(
            obs,
            "postcondition",
            "terminal_chat_reply_postamble_floor",
            "nist_pqc_terminal_chat_reply_postamble_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_render_heading_floor",
            "nist_pqc_briefing_render_heading_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_rendered_required_section_label_floor",
            "nist_pqc_briefing_rendered_required_section_label_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_document_layout",
            "nist_pqc_briefing_document_layout_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_story_headers_absent",
            "nist_pqc_briefing_story_headers_absent_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_comparison_absent",
            "nist_pqc_briefing_comparison_absent_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_required_section_floor",
            "nist_pqc_briefing_required_section_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_query_grounding_floor",
            "nist_pqc_briefing_query_grounding_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_standard_identifier_floor",
            "nist_pqc_briefing_standard_identifier_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_authority_standard_identifier_floor",
            "nist_pqc_briefing_authority_standard_identifier_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_summary_inventory_floor",
            "nist_pqc_briefing_summary_inventory_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_narrative_aggregation_floor",
            "nist_pqc_briefing_narrative_aggregation_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_evidence_block_floor",
            "nist_pqc_briefing_evidence_block_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_primary_authority_source_floor",
            "nist_pqc_briefing_primary_authority_source_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_temporal_anchor_floor",
            "nist_pqc_briefing_temporal_anchor_floor_observed",
        ),
        observed_receipt(
            obs,
            "verification",
            "briefing_postamble_floor",
            "nist_pqc_briefing_postamble_floor_observed",
        ),
        observed_receipt(
            obs,
            "completion_gate",
            "contract_gate",
            "nist_pqc_completion_gate_observed",
        ),
        EvidenceReceipt {
            key: "nist_pqc_currentness_required_true".to_string(),
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

fn summary_field(summary: &str, key: &str) -> Option<String> {
    summary
        .split(';')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(field, value)| {
            field
                .trim()
                .eq_ignore_ascii_case(key)
                .then(|| value.trim().to_string())
        })
}

fn summary_bool_field(summary: &str, key: &str) -> Option<bool> {
    summary_field(summary, key).and_then(|value| match value.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    })
}

fn summary_usize_field(summary: &str, key: &str) -> Option<usize> {
    summary_field(summary, key).and_then(|value| value.parse::<usize>().ok())
}

fn summary_string_field(summary: &str, key: &str) -> Option<String> {
    summary_field(summary, key)
}

fn sha256_prefixed(value: &str) -> String {
    sha256(value.as_bytes())
        .map(|digest| format!("sha256:{}", hex::encode(digest.as_ref())))
        .unwrap_or_else(|_| "sha256:unavailable".to_string())
}

fn observe_terminal_artifact(final_reply: &str) -> TerminalArtifactObservation {
    let lines = final_reply
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    let heading_present = lines.first().is_some_and(|line| {
        line.starts_with("Briefing for '") || line.starts_with("Web briefing (as of ")
    });
    let story_header_count = lines
        .iter()
        .filter(|line| {
            line.strip_prefix("Story ")
                .and_then(|rest| rest.split_once(':'))
                .is_some()
        })
        .count();
    let comparison_label_count = lines
        .iter()
        .filter(|line| line.eq_ignore_ascii_case("Comparison:"))
        .count();
    let run_date_present = lines.iter().any(|line| {
        line.starts_with("Run date (UTC):") && !line["Run date (UTC):".len()..].trim().is_empty()
    });
    let run_timestamp_present = lines.iter().any(|line| {
        line.starts_with("Run timestamp (UTC):")
            && !line["Run timestamp (UTC):".len()..].trim().is_empty()
    });
    let overall_confidence_present = lines.iter().any(|line| {
        line.starts_with("Overall confidence:")
            && !line["Overall confidence:".len()..].trim().is_empty()
    });

    TerminalArtifactObservation {
        reply_sha256: sha256_prefixed(final_reply),
        char_count: final_reply.chars().count(),
        heading_present,
        story_header_count,
        comparison_label_count,
        run_date_present,
        run_timestamp_present,
        overall_confidence_present,
    }
}

fn collect_environment_receipts(obs: &RunObservation) -> Vec<EnvironmentEvidenceReceipt> {
    [
        "latest_nist_pqc_briefing_fixture_mode",
        "latest_nist_pqc_briefing_fixture_root",
        "latest_nist_pqc_briefing_fixture_manifest_path",
        "latest_nist_pqc_briefing_run_unique_num",
        "latest_nist_pqc_briefing_current_utc_date",
        "latest_nist_pqc_briefing_current_utc_timestamp_ms",
        "latest_nist_pqc_briefing_fixture",
        "latest_nist_pqc_briefing_fixture_root_exists",
        "latest_nist_pqc_briefing_manifest_exists",
        "latest_nist_pqc_briefing_current_utc_date_post_run",
        "latest_nist_pqc_briefing_scope",
        "latest_nist_pqc_briefing_cleanup_root_exists",
        "latest_nist_pqc_briefing_cleanup_manifest_exists",
        "latest_nist_pqc_briefing_cleanup",
    ]
    .into_iter()
    .map(|key| EnvironmentEvidenceReceipt {
        key,
        observed_value: environment_value(obs, &format!("env_receipt::{key}")).unwrap_or_default(),
        probe_source: environment_value(obs, &format!("env_receipt::{key}_probe_source"))
            .unwrap_or_else(|| EXPECTED_FIXTURE_PROBE_SOURCE.to_string()),
        timestamp_ms: environment_u64(obs, &format!("env_receipt::{key}_timestamp_ms"))
            .unwrap_or(obs.run_timestamp_ms),
        satisfied: environment_bool(obs, &format!("env_receipt::{key}_satisfied")).unwrap_or(false),
    })
    .collect()
}

fn serialize_evidence_receipts(receipts: &[EvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}

fn serialize_environment_receipts(receipts: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(receipts).unwrap_or_else(|_| "[]".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        benchmark_briefing_authority_standard_inventory_quality_met,
        benchmark_briefing_standard_inventory_quality_met,
        benchmark_briefing_summary_inventory_quality_met,
        benchmark_selected_source_identifier_coverage_quality_met, is_official_nist_source,
        observe_terminal_artifact, official_nist_selected_alignment_evidence_present,
    };
    use crate::capabilities_suite::types::WebObservation;

    #[test]
    fn official_nist_source_detection_accepts_nist_publication_hosts() {
        assert!(is_official_nist_source(
            "https://csrc.nist.gov/pubs/fips/203/final"
        ));
        assert!(is_official_nist_source("https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"));
        assert!(is_official_nist_source("https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf"));
        assert!(!is_official_nist_source("https://example.com/pqc"));
    }

    #[test]
    fn terminal_artifact_observation_rejects_story_collection_output() {
        let bad_output = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T12:19:24Z UTC)\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high";
        let observation = observe_terminal_artifact(bad_output);

        assert!(!observation.heading_present);
        assert_eq!(observation.story_header_count, 1);
        assert_eq!(observation.comparison_label_count, 1);
        assert!(observation.run_date_present);
        assert!(observation.run_timestamp_present);
        assert!(observation.overall_confidence_present);
    }

    #[test]
    fn terminal_artifact_observation_accepts_document_briefing_shape() {
        let good_output = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nWhat happened:\n- NIST finalized FIPS 203, FIPS 204, and FIPS 205 for ML-KEM, ML-DSA, and SLH-DSA.\n\nKey evidence:\n- NIST states these standards are mandatory for federal systems and broadly adopted.\n\nCitations:\n- Post-quantum cryptography | NIST | https://www.nist.gov/pqc | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: high";
        let observation = observe_terminal_artifact(good_output);

        assert!(observation.heading_present);
        assert_eq!(observation.story_header_count, 0);
        assert_eq!(observation.comparison_label_count, 0);
        assert!(observation.run_date_present);
        assert!(observation.run_timestamp_present);
        assert!(observation.overall_confidence_present);
    }

    #[test]
    fn benchmark_inventory_quality_helpers_accept_single_required_identifier_floor() {
        assert!(benchmark_briefing_standard_inventory_quality_met(
            true, 1, 1, 4, 2, 3
        ));
        assert!(benchmark_briefing_authority_standard_inventory_quality_met(
            true, 1, 1, 4
        ));
    }

    #[test]
    fn benchmark_summary_inventory_quality_helper_accepts_authority_only_optional_inventory() {
        assert!(benchmark_briefing_summary_inventory_quality_met(
            true, 1, 0, 3, 3, 3, 1
        ));
        assert!(!benchmark_briefing_summary_inventory_quality_met(
            true, 1, 0, 1, 1, 3, 1
        ));
    }

    #[test]
    fn selected_source_identifier_coverage_quality_uses_dynamic_required_group_floor() {
        assert!(benchmark_selected_source_identifier_coverage_quality_met(
            true, true, 2, 1, 2, 2, 2
        ));
        assert!(!benchmark_selected_source_identifier_coverage_quality_met(
            true, true, 2, 1, 1, 2, 2
        ));
    }

    #[test]
    fn official_nist_alignment_evidence_uses_selected_aligned_sources() {
        let web = WebObservation {
            selected_source_subject_alignment_floor_met: Some(true),
            selected_source_urls: vec![
                "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/announcing-approval-three-federal-information-processing-standards-fips".to_string(),
            ],
            selected_source_subject_alignment_urls: vec![
                "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/announcing-approval-three-federal-information-processing-standards-fips".to_string(),
            ],
            semantic_subject_alignment_urls: vec![
                "https://www.washingtontechnology.com/opinion/2025/06/why-federal-agencies-must-act-now-post-quantum-cryptography/405738/".to_string(),
            ],
            ..WebObservation::default()
        };

        assert!(official_nist_selected_alignment_evidence_present(&web));
    }
}
