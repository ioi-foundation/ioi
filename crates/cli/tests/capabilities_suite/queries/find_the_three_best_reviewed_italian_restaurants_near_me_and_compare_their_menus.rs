use ioi_types::app::agentic::IntentScopeProfile;
use serde::Serialize;
use std::collections::BTreeSet;

use super::super::types::{
    cec_receipt_bool, cec_receipt_latest_values, cec_receipt_satisfied, cec_receipt_usize,
    environment_bool, environment_u64, environment_value, has_cec_receipt, has_cec_stage,
    observation_has_tool_name, truncate_chars, ExecutionProfile, LocalCheck, LocalJudgeResult,
    QueryCase, RunObservation,
};

const CASE_ID: &str =
    "find_the_three_best_reviewed_italian_restaurants_near_me_and_compare_their_menus";
const EXPECTED_FIXTURE_MODE: &str = "runtime_locality_observation_fixture_v2";
const EXPECTED_FIXTURE_PROBE_SOURCE: &str = "harness.restaurants_near_me_fixture";

fn is_contract_error_class(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "executioncontractviolation"
            | "discoverymissing"
            | "synthesisfailed"
            | "executionfailedterminal"
            | "verificationmissing"
            | "postconditionfailed"
    )
}

fn normalized_url_set(urls: &[String]) -> BTreeSet<String> {
    urls.iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

fn is_geo_scoped_entity_expansion_flow(obs: &RunObservation) -> bool {
    obs.web
        .as_ref()
        .and_then(|web| web.retrieval_contract.as_ref())
        .map(|contract| {
            contract.comparison_required
                && contract.runtime_locality_required
                && contract.geo_scoped_detail_required
                && contract.discovery_surface_required
                && contract.entity_diversity_required
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone, Serialize)]
struct EnvironmentEvidenceReceipt {
    key: &'static str,
    observed_value: String,
    probe_source: String,
    timestamp_ms: u64,
    satisfied: bool,
}

pub fn case() -> QueryCase {
    QueryCase {
        id: CASE_ID,
        query: "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        success_definition: "Return three restaurants grounded to the observed runtime locality with structured citations, explicit menu comparison, final-source evidence, runtime locality evidence, and cleanup-backed observation evidence.",
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
    let fixture_mode = environment_value(obs, "env_evidence::restaurants_near_me_fixture_mode")
        .unwrap_or_default();
    let fixture_probe_source = environment_value(
        obs,
        "env_evidence::restaurants_near_me_fixture_probe_source",
    )
    .unwrap_or_else(|| EXPECTED_FIXTURE_PROBE_SOURCE.to_string());
    let fixture_timestamp_ms = environment_u64(
        obs,
        "env_evidence::restaurants_near_me_fixture_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let fixture_satisfied =
        environment_bool(obs, "env_evidence::restaurants_near_me_fixture_satisfied")
            .unwrap_or(false);
    let manifest_seeded_satisfied = environment_bool(
        obs,
        "env_evidence::restaurants_near_me_manifest_seeded_satisfied",
    )
    .unwrap_or(false);

    let locality_env_key =
        environment_value(obs, "env_evidence::restaurants_near_me_locality_env_key")
            .unwrap_or_default();
    let locality_observed_value = environment_value(
        obs,
        "env_evidence::restaurants_near_me_locality_observed_value",
    )
    .unwrap_or_default();
    let locality_probe_source = environment_value(
        obs,
        "env_evidence::restaurants_near_me_locality_probe_source",
    )
    .unwrap_or_else(|| format!("{}.preflight", EXPECTED_FIXTURE_PROBE_SOURCE));
    let locality_timestamp_ms = environment_u64(
        obs,
        "env_evidence::restaurants_near_me_locality_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let locality_observation_satisfied = environment_bool(
        obs,
        "env_evidence::restaurants_near_me_locality_observation_satisfied",
    )
    .unwrap_or(false);
    let scope_satisfied =
        environment_bool(obs, "env_evidence::restaurants_near_me_scope_satisfied").unwrap_or(false);
    let post_run_locality_unchanged_satisfied = environment_bool(
        obs,
        "env_evidence::restaurants_near_me_locality_unchanged_post_run_satisfied",
    )
    .unwrap_or(false);

    let cleanup_probe_source = environment_value(
        obs,
        "env_evidence::restaurants_near_me_cleanup_probe_source",
    )
    .unwrap_or_else(|| format!("{}.cleanup_probe", EXPECTED_FIXTURE_PROBE_SOURCE));
    let cleanup_timestamp_ms = environment_u64(
        obs,
        "env_evidence::restaurants_near_me_cleanup_timestamp_ms",
    )
    .unwrap_or(obs.run_timestamp_ms);
    let cleanup_satisfied =
        environment_bool(obs, "env_evidence::restaurants_near_me_cleanup_satisfied")
            .unwrap_or(false);
    let cleanup_locality_unchanged_satisfied = environment_bool(
        obs,
        "env_evidence::restaurants_near_me_cleanup_locality_unchanged_satisfied",
    )
    .unwrap_or(false);
    let cleanup_locality_observed_value = environment_value(
        obs,
        "env_evidence::restaurants_near_me_cleanup_locality_observed_value",
    )
    .unwrap_or_default();

    let runtime_locality_required = web.runtime_locality_required.unwrap_or(false);
    let runtime_locality_scope = web.runtime_locality_scope.clone().unwrap_or_default();
    let runtime_locality_satisfied = if runtime_locality_required {
        !runtime_locality_scope.trim().is_empty()
    } else {
        true
    };
    let runtime_locality_contract_evidence_present = runtime_locality_required
        && runtime_locality_satisfied
        && !runtime_locality_scope.trim().is_empty();
    let runtime_query_contract = web.query_contract.clone().unwrap_or_default();
    let runtime_locality_alignment_present = web.runtime_locality_alignment.unwrap_or(false);

    let web_search_path_seen = observation_has_tool_name(obs, "web__search");
    let web_read_path_seen = observation_has_tool_name(obs, "web__read");
    let direct_fetch_path_seen = observation_has_tool_name(obs, "http__fetch");
    let tool_and_route_path_evidence_present =
        web_search_path_seen && web_read_path_seen && !direct_fetch_path_seen;

    let web_min_sources = web.min_sources.unwrap_or(0);
    let web_sources_success = web.sources_success.unwrap_or(0);
    let source_floor_receipts_present = web.source_floor_met.unwrap_or(false)
        && web_min_sources >= 3
        && web_sources_success >= web_min_sources;

    let selected_source_quality_floor_met = web.selected_source_quality_floor_met.unwrap_or(false);
    let selected_source_urls =
        cec_receipt_latest_values(obs, "verification", "selected_source_url");
    let selected_source_count = web
        .selected_source_count
        .unwrap_or_else(|| selected_source_urls.len());
    let semantic_subject_alignment_required =
        web.semantic_subject_alignment_required.unwrap_or(false);
    let semantic_subject_alignment_floor_met = web
        .semantic_subject_alignment_floor_met
        .unwrap_or(!semantic_subject_alignment_required);
    let semantic_subject_alignment_urls =
        cec_receipt_latest_values(obs, "discovery", "semantic_subject_alignment_url");
    let selected_source_subject_alignment_floor_met = web
        .selected_source_subject_alignment_floor_met
        .unwrap_or(!semantic_subject_alignment_required);
    let selected_source_subject_alignment_urls =
        cec_receipt_latest_values(obs, "verification", "selected_source_subject_alignment_url");
    let final_selected_source_distinct_domains = web.selected_source_distinct_domains.unwrap_or(0);
    let local_business_entity_floor_met = web.local_business_entity_floor_met.unwrap_or(false);
    let local_business_entity_anchor_floor_met =
        web.local_business_entity_anchor_floor_met.unwrap_or(false);
    let local_business_entity_matched_names =
        cec_receipt_latest_values(obs, "verification", "local_business_entity_name");
    let local_business_entity_source_urls =
        cec_receipt_latest_values(obs, "verification", "local_business_entity_source_url");
    let local_business_entity_anchor_source_urls = cec_receipt_latest_values(
        obs,
        "verification",
        "local_business_entity_anchor_source_url",
    );
    let local_business_entity_anchor_mismatched_urls = cec_receipt_latest_values(
        obs,
        "verification",
        "local_business_entity_anchor_mismatched_url",
    );
    let local_business_entity_receipts_present = local_business_entity_floor_met
        && local_business_entity_matched_names.len() >= 3
        && local_business_entity_source_urls.len() >= 3;
    let local_business_entity_anchor_receipt_seen = has_cec_receipt(
        obs,
        "verification",
        "local_business_entity_anchor_floor",
        Some(true),
    );
    let local_business_entity_anchor_receipts_present = local_business_entity_anchor_receipt_seen
        && local_business_entity_anchor_floor_met
        && local_business_entity_anchor_source_urls.len() >= 3
        && local_business_entity_anchor_mismatched_urls.is_empty();
    let local_business_menu_surface_required =
        cec_receipt_bool(obs, "verification", "local_business_menu_surface_required")
            .unwrap_or(true);
    let local_business_menu_surface_receipt_seen = has_cec_receipt(
        obs,
        "verification",
        "local_business_menu_surface_floor",
        Some(true),
    );
    let local_business_menu_surface_source_urls = cec_receipt_latest_values(
        obs,
        "verification",
        "local_business_menu_surface_source_url",
    );
    let local_business_menu_inventory_receipt_seen = has_cec_receipt(
        obs,
        "verification",
        "local_business_menu_inventory_floor",
        Some(true),
    );
    let local_business_menu_inventory_floor_met =
        cec_receipt_satisfied(obs, "verification", "local_business_menu_inventory_floor")
            .unwrap_or(false);
    let local_business_menu_inventory_source_urls = cec_receipt_latest_values(
        obs,
        "verification",
        "local_business_menu_inventory_source_url",
    );
    let local_business_menu_inventory_items =
        cec_receipt_latest_values(obs, "verification", "local_business_menu_inventory_item");
    let local_business_menu_inventory_total_item_count = cec_receipt_usize(
        obs,
        "verification",
        "local_business_menu_inventory_total_item_count",
    )
    .unwrap_or(local_business_menu_inventory_items.len());
    let local_business_menu_surface_receipts_present = !local_business_menu_surface_required
        || (local_business_menu_surface_receipt_seen
            && local_business_menu_surface_source_urls.len() >= 3
            && normalized_url_set(&local_business_menu_surface_source_urls)
                == normalized_url_set(&selected_source_urls));
    let local_business_menu_inventory_receipts_present = !local_business_menu_surface_required
        || (local_business_menu_inventory_receipt_seen
            && local_business_menu_inventory_floor_met
            && local_business_menu_inventory_source_urls.len() >= 3
            && normalized_url_set(&local_business_menu_inventory_source_urls)
                == normalized_url_set(&selected_source_urls)
            && local_business_menu_inventory_total_item_count >= 6
            && !local_business_menu_inventory_items.is_empty());
    let final_story_slots_observed = web.story_slots_observed.unwrap_or(0);
    let final_story_slot_floor_met = web.story_slot_floor_met.unwrap_or(false);
    let final_story_citation_floor_met = web.story_citation_floor_met.unwrap_or(false);
    let final_comparison_required = web
        .retrieval_contract
        .as_ref()
        .map(|contract| contract.comparison_required)
        .unwrap_or(true);
    let final_comparison_ready = web.comparison_ready.unwrap_or(false);
    let geo_scoped_entity_expansion_flow = is_geo_scoped_entity_expansion_flow(obs);
    let objective_specific_restaurant_comparison_evidence_present = final_story_slots_observed >= 3
        && final_story_slot_floor_met
        && final_story_citation_floor_met
        && local_business_menu_surface_receipts_present
        && local_business_menu_inventory_receipts_present
        && (!final_comparison_required || final_comparison_ready);
    let final_selected_source_urls_match_entity_sources = !selected_source_urls.is_empty()
        && normalized_url_set(&selected_source_urls)
            == normalized_url_set(&local_business_entity_source_urls);
    let semantic_subject_alignment_receipts_present = if !semantic_subject_alignment_required {
        true
    } else if geo_scoped_entity_expansion_flow {
        semantic_subject_alignment_floor_met
            && selected_source_subject_alignment_floor_met
            && !semantic_subject_alignment_urls.is_empty()
            && !selected_source_subject_alignment_urls.is_empty()
            && local_business_entity_receipts_present
            && local_business_entity_anchor_receipts_present
            && selected_source_count >= 3
    } else {
        semantic_subject_alignment_floor_met
            && selected_source_subject_alignment_floor_met
            && !selected_source_subject_alignment_urls.is_empty()
            && semantic_subject_alignment_urls.len() >= selected_source_subject_alignment_urls.len()
    };
    let final_selected_source_entity_diversity_floor_met = local_business_entity_source_urls.len()
        >= 3
        && local_business_entity_matched_names.len() >= 3;
    let final_selected_source_independence_present = final_selected_source_distinct_domains >= 3
        || final_selected_source_entity_diversity_floor_met;
    let selected_source_quality_receipt_seen = has_cec_receipt(
        obs,
        "verification",
        "selected_source_quality_floor",
        Some(true),
    );
    let selected_source_quality_receipts_present = if geo_scoped_entity_expansion_flow {
        selected_source_quality_receipt_seen
            && selected_source_quality_floor_met
            && selected_source_urls.len() >= 3
            && final_selected_source_independence_present
            && semantic_subject_alignment_receipts_present
            && final_story_slot_floor_met
            && final_selected_source_urls_match_entity_sources
            && local_business_entity_receipts_present
            && local_business_entity_anchor_receipts_present
            && local_business_menu_inventory_receipts_present
    } else {
        selected_source_quality_receipt_seen
            && selected_source_count >= 3
            && final_selected_source_independence_present
            && semantic_subject_alignment_receipts_present
            && final_story_slot_floor_met
            && selected_source_quality_floor_met
            && local_business_menu_inventory_receipts_present
    };
    let cec_execution_seen = has_cec_stage(obs, "execution", Some(true));
    let cec_verification_seen = has_cec_stage(obs, "verification", Some(true));
    let cec_contract_gate_seen =
        has_cec_receipt(obs, "completion_gate", "contract_gate", Some(true));
    let cec_contract_gate_satisfied =
        cec_contract_gate_seen || (cec_execution_seen && cec_verification_seen);
    let cec_contract_gate_failed = obs.cec_receipts.iter().any(|receipt| {
        receipt.stage.eq_ignore_ascii_case("completion_gate")
            && receipt.key.eq_ignore_ascii_case("contract_gate")
            && !receipt.satisfied
    });
    let typed_contract_failure_present = cec_contract_gate_failed
        || obs
            .action_error_classes
            .iter()
            .any(|value| is_contract_error_class(value))
        || obs
            .routing_failure_classes
            .iter()
            .any(|value| is_contract_error_class(value));
    let contract_failure_markers_absent = !typed_contract_failure_present;
    let completion_evidence_present =
        obs.completed && !obs.failed && obs.chat_reply_count > 0 && cec_contract_gate_satisfied;

    let environment_receipts = build_environment_receipts(
        obs,
        fixture_mode,
        fixture_probe_source,
        fixture_timestamp_ms,
        fixture_satisfied,
        manifest_seeded_satisfied,
        locality_env_key,
        locality_observed_value,
        locality_probe_source,
        locality_timestamp_ms,
        locality_observation_satisfied,
        scope_satisfied,
        post_run_locality_unchanged_satisfied,
        runtime_locality_required,
        runtime_locality_satisfied,
        runtime_locality_scope.clone(),
        runtime_query_contract.clone(),
        runtime_locality_alignment_present,
        cleanup_probe_source,
        cleanup_timestamp_ms,
        cleanup_satisfied,
        cleanup_locality_unchanged_satisfied,
        cleanup_locality_observed_value,
    );
    let environment_receipts_satisfied =
        environment_receipts.iter().all(|receipt| receipt.satisfied);

    let independent_channel_count = [
        completion_evidence_present,
        objective_specific_restaurant_comparison_evidence_present,
        tool_and_route_path_evidence_present,
        runtime_locality_contract_evidence_present,
        runtime_locality_alignment_present,
        source_floor_receipts_present,
        semantic_subject_alignment_receipts_present,
        selected_source_quality_receipts_present,
        local_business_entity_receipts_present,
        local_business_entity_anchor_receipts_present,
        local_business_menu_surface_receipts_present,
        local_business_menu_inventory_receipts_present,
        cec_contract_gate_satisfied,
        environment_receipts_satisfied,
        contract_failure_markers_absent,
    ]
    .into_iter()
    .filter(|flag| *flag)
    .count();
    let independent_runtime_evidence_channels_present =
        objective_specific_restaurant_comparison_evidence_present && independent_channel_count >= 8;

    let checks = vec![
        LocalCheck::new(
            "completion_evidence_present",
            completion_evidence_present,
            format!(
                "status={} completed={} failed={} chat_reply_count={} cec_contract_gate_satisfied={}",
                obs.final_status,
                obs.completed,
                obs.failed,
                obs.chat_reply_count,
                cec_contract_gate_satisfied
            ),
        ),
        LocalCheck::new(
            "objective_specific_restaurant_comparison_evidence_present",
            objective_specific_restaurant_comparison_evidence_present,
            format!(
                "final_story_slots_observed={} story_slot_floor_met={} story_citation_floor_met={} comparison_required={} comparison_ready={}",
                final_story_slots_observed,
                final_story_slot_floor_met,
                final_story_citation_floor_met,
                final_comparison_required,
                final_comparison_ready,
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
            "runtime_locality_contract_evidence_present",
            runtime_locality_contract_evidence_present,
            format!(
                "required={} satisfied={} scope={} query_contract={}",
                runtime_locality_required,
                runtime_locality_satisfied,
                runtime_locality_scope,
                runtime_query_contract
            ),
        ),
        LocalCheck::new(
            "runtime_locality_alignment_present",
            runtime_locality_alignment_present,
            format!(
                "scope={} query_contract={} query_contract_locality_alignment_receipt={}",
                runtime_locality_scope,
                runtime_query_contract,
                runtime_locality_alignment_present
            ),
        ),
        LocalCheck::new(
            "source_floor_receipts_present",
            source_floor_receipts_present,
            format!(
                "web_min_sources={} web_sources_success={} selected_source_count={} selected_source_urls={:?}",
                web_min_sources,
                web_sources_success,
                web.selected_source_count.unwrap_or(0),
                selected_source_urls
            ),
        ),
        LocalCheck::new(
            "semantic_subject_alignment_receipts_present",
            semantic_subject_alignment_receipts_present,
            format!(
                "required={} discovery_floor_met={} selected_floor_met={} geo_scoped_entity_expansion_flow={} discovery_urls={:?} selected_urls={:?} final_selected_source_urls_match_entity_sources={} anchor_source_urls={:?}",
                semantic_subject_alignment_required,
                semantic_subject_alignment_floor_met,
                selected_source_subject_alignment_floor_met,
                geo_scoped_entity_expansion_flow,
                semantic_subject_alignment_urls,
                selected_source_subject_alignment_urls,
                final_selected_source_urls_match_entity_sources,
                local_business_entity_anchor_source_urls,
            ),
        ),
        LocalCheck::new(
            "selected_source_quality_receipts_present",
            selected_source_quality_receipts_present,
            format!(
                "quality_floor_receipt_seen={} quality_floor_receipt_met={} geo_scoped_entity_expansion_flow={} final_selected_source_distinct_domains={} entity_diversity_floor_met={} final_selected_source_urls_match_entity_sources={} selected_source_urls={:?}",
                selected_source_quality_receipt_seen,
                selected_source_quality_floor_met,
                geo_scoped_entity_expansion_flow,
                final_selected_source_distinct_domains,
                final_selected_source_entity_diversity_floor_met,
                final_selected_source_urls_match_entity_sources,
                selected_source_urls
            ),
        ),
        LocalCheck::new(
            "local_business_entity_receipts_present",
            local_business_entity_receipts_present,
            format!(
                "floor_met={} matched_names={:?} source_urls={:?}",
                local_business_entity_floor_met,
                local_business_entity_matched_names,
                local_business_entity_source_urls
            ),
        ),
        LocalCheck::new(
            "local_business_entity_anchor_receipts_present",
            local_business_entity_anchor_receipts_present,
            format!(
                "receipt_seen={} floor_met={} source_urls={:?} mismatched_urls={:?}",
                local_business_entity_anchor_receipt_seen,
                local_business_entity_anchor_floor_met,
                local_business_entity_anchor_source_urls,
                local_business_entity_anchor_mismatched_urls
            ),
        ),
        LocalCheck::new(
            "local_business_menu_surface_receipts_present",
            local_business_menu_surface_receipts_present,
            format!(
                "required={} receipt_seen={} selected_source_urls={:?} menu_surface_source_urls={:?}",
                local_business_menu_surface_required,
                local_business_menu_surface_receipt_seen,
                selected_source_urls,
                local_business_menu_surface_source_urls
            ),
        ),
        LocalCheck::new(
            "local_business_menu_inventory_receipts_present",
            local_business_menu_inventory_receipts_present,
            format!(
                "receipt_seen={} floor_met={} selected_source_urls={:?} menu_inventory_source_urls={:?} total_item_count={} menu_inventory_items={:?}",
                local_business_menu_inventory_receipt_seen,
                local_business_menu_inventory_floor_met,
                selected_source_urls,
                local_business_menu_inventory_source_urls,
                local_business_menu_inventory_total_item_count,
                local_business_menu_inventory_items
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
            "environment_receipts_satisfied",
            environment_receipts_satisfied,
            serialize_environment_receipts(&environment_receipts),
        ),
        LocalCheck::new(
            "contract_failure_markers_absent",
            contract_failure_markers_absent,
            truncate_chars(
                &format!(
                    "typed_contract_failure_present={} action_error_classes={:?} routing_failure_classes={:?} event_excerpt={:?}",
                    typed_contract_failure_present,
                    obs.action_error_classes,
                    obs.routing_failure_classes,
                    obs.event_excerpt
                ),
                320,
            ),
        ),
        LocalCheck::new(
            "independent_runtime_evidence_channels_present",
            independent_runtime_evidence_channels_present,
            format!(
                "independent_channel_count={} objective_specific_restaurant_comparison_evidence_present={}",
                independent_channel_count,
                objective_specific_restaurant_comparison_evidence_present
            ),
        ),
    ];

    LocalJudgeResult::from_checks(checks)
}

#[allow(clippy::too_many_arguments)]
fn build_environment_receipts(
    obs: &RunObservation,
    fixture_mode: String,
    fixture_probe_source: String,
    fixture_timestamp_ms: u64,
    fixture_satisfied: bool,
    manifest_seeded_satisfied: bool,
    locality_env_key: String,
    locality_observed_value: String,
    locality_probe_source: String,
    locality_timestamp_ms: u64,
    locality_observation_satisfied: bool,
    scope_satisfied: bool,
    post_run_locality_unchanged_satisfied: bool,
    runtime_locality_required: bool,
    runtime_locality_satisfied: bool,
    runtime_locality_scope: String,
    runtime_query_contract: String,
    runtime_locality_alignment_present: bool,
    cleanup_probe_source: String,
    cleanup_timestamp_ms: u64,
    cleanup_satisfied: bool,
    cleanup_locality_unchanged_satisfied: bool,
    cleanup_locality_observed_value: String,
) -> Vec<EnvironmentEvidenceReceipt> {
    vec![
        EnvironmentEvidenceReceipt {
            key: "restaurants_fixture_mode_observed",
            observed_value: fixture_mode.clone(),
            probe_source: if fixture_probe_source.trim().is_empty() {
                EXPECTED_FIXTURE_PROBE_SOURCE.to_string()
            } else {
                fixture_probe_source
            },
            timestamp_ms: fixture_timestamp_ms,
            satisfied: fixture_mode.eq_ignore_ascii_case(EXPECTED_FIXTURE_MODE) && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "restaurants_fixture_manifest_observed",
            observed_value: format!(
                "manifest_seeded_satisfied={} fixture_satisfied={}",
                manifest_seeded_satisfied, fixture_satisfied
            ),
            probe_source: EXPECTED_FIXTURE_PROBE_SOURCE.to_string(),
            timestamp_ms: fixture_timestamp_ms,
            satisfied: manifest_seeded_satisfied && fixture_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "restaurants_locality_env_observed",
            observed_value: format!(
                "env_key={} observed_value={} locality_observation_satisfied={} scope_satisfied={} post_run_locality_unchanged_satisfied={}",
                locality_env_key,
                locality_observed_value,
                locality_observation_satisfied,
                scope_satisfied,
                post_run_locality_unchanged_satisfied
            ),
            probe_source: locality_probe_source,
            timestamp_ms: locality_timestamp_ms,
            satisfied: locality_observation_satisfied && scope_satisfied,
        },
        EnvironmentEvidenceReceipt {
            key: "restaurants_runtime_locality_contract_observed",
            observed_value: format!(
                "required={} satisfied={} scope={} query_contract={}",
                runtime_locality_required,
                runtime_locality_satisfied,
                runtime_locality_scope,
                runtime_query_contract
            ),
            probe_source: "RunObservation.cec_receipts".to_string(),
            timestamp_ms: obs.run_timestamp_ms,
            satisfied: runtime_locality_required
                && runtime_locality_satisfied
                && !runtime_locality_scope.trim().is_empty()
                && runtime_locality_alignment_present,
        },
        EnvironmentEvidenceReceipt {
            key: "restaurants_fixture_cleanup_observed",
            observed_value: format!(
                "cleanup_satisfied={} cleanup_locality_unchanged_satisfied={} cleanup_locality_observed_value={}",
                cleanup_satisfied,
                cleanup_locality_unchanged_satisfied,
                cleanup_locality_observed_value
            ),
            probe_source: cleanup_probe_source,
            timestamp_ms: cleanup_timestamp_ms,
            satisfied: cleanup_satisfied && cleanup_locality_unchanged_satisfied,
        },
    ]
}

fn serialize_environment_receipts(evidence: &[EnvironmentEvidenceReceipt]) -> String {
    serde_json::to_string(evidence).unwrap_or_else(|_| "[]".to_string())
}
