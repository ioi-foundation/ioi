use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{InferenceOptions, WebRetrievalContract, WebSource};
use serde::Serialize;
use std::sync::Arc;

use super::util::normalize_url_for_id;
use crate::agentic::desktop::service::step::queue::web_pipeline::{
    build_query_constraint_projection, candidate_constraint_compatibility,
    candidate_time_sensitive_resolvable_payload, compatibility_passes_projection,
    explicit_query_scope_hint, is_search_hub_url,
    local_business_search_entity_anchor_tokens_with_contract, prefers_single_fact_snapshot,
    query_is_generic_headline_collection, query_metric_axes,
    query_prefers_document_briefing_layout, query_requests_comparison,
    query_requires_runtime_locality_scope, required_citations_per_story, required_story_count,
    source_matches_local_business_search_entity_anchor,
};
use crate::agentic::desktop::service::step::signals::analyze_query_facets;

const WEB_RETRIEVAL_CONTRACT_VERSION: &str = "web_retrieval_contract.v1";
pub(crate) const WEB_SOURCE_ALIGNMENT_MAX_SOURCES: usize = 40;

#[derive(Debug, Serialize)]
struct SemanticAlignmentSourcePayload {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rank: Option<u32>,
}

#[derive(Debug, Serialize)]
struct SemanticAlignmentPayload<'a> {
    query_contract: &'a str,
    retrieval_contract: &'a WebRetrievalContract,
    sources: Vec<SemanticAlignmentSourcePayload>,
}

pub(crate) fn contract_requires_geo_scoped_entity_expansion(
    contract: &WebRetrievalContract,
) -> bool {
    contract.entity_diversity_required
        && contract.entity_cardinality_min > 1
        && contract.comparison_required
        && contract.link_collection_preferred
        && contract.canonical_link_out_preferred
        && contract.discovery_surface_required
        && (contract.runtime_locality_required || contract.geo_scoped_detail_required)
}

pub(crate) fn contract_requires_semantic_source_alignment(contract: &WebRetrievalContract) -> bool {
    contract.entity_diversity_required
        || contract.scalar_measure_required
        || (contract.currentness_required
            && contract.source_independence_min > 1
            && !contract.ordered_collection_preferred)
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let trimmed = raw.trim();
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}')?;
    (end >= start).then_some(&trimmed[start..=end])
}

fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    let marker = "source_url=";
    let lower = excerpt.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    let candidate = excerpt
        .get(start..)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| "|,;:!?)]}\"'".contains(ch))
        .trim();
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn semantic_alignment_candidate_url(source: &WebSource) -> String {
    let trimmed = source.url.trim();
    if !is_search_hub_url(trimmed) {
        return trimmed.to_string();
    }
    source
        .snippet
        .as_deref()
        .and_then(source_url_from_metadata_excerpt)
        .unwrap_or_else(|| trimmed.to_string())
}

fn normalized_query_contract<'a>(query: &'a str, query_contract: Option<&'a str>) -> &'a str {
    query_contract
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| query.trim())
}

fn structural_source_independence_floor(contract: &WebRetrievalContract) -> u32 {
    let direct_single_record_snapshot = contract.entity_cardinality_min <= 1
        && contract.structured_record_preferred
        && !contract.comparison_required
        && !contract.ordered_collection_preferred
        && !contract.link_collection_preferred
        && !contract.canonical_link_out_preferred;
    if direct_single_record_snapshot {
        1
    } else if contract.entity_cardinality_min > 1 || contract.comparison_required {
        contract.entity_cardinality_min.max(2)
    } else if contract.currentness_required {
        2
    } else {
        1
    }
}

fn lint_web_retrieval_contract(
    query: &str,
    query_contract: Option<&str>,
    mut contract: WebRetrievalContract,
) -> Result<WebRetrievalContract, String> {
    let raw_query = query.trim();
    let normalized_query_contract = normalized_query_contract(query, query_contract);
    let facets = analyze_query_facets(normalized_query_contract);
    let comparison_required = query_requests_comparison(normalized_query_contract);
    let document_briefing_layout =
        query_prefers_document_briefing_layout(normalized_query_contract);
    let explicit_entity_cardinality = if document_briefing_layout && !comparison_required {
        1
    } else {
        required_story_count(normalized_query_contract).clamp(1, 6) as u32
    };
    let structural_citation_count_min =
        required_citations_per_story(normalized_query_contract).clamp(1, 4) as u32;
    let explicit_locality_scope_present = crate::agentic::desktop::service::step::queue::web_pipeline::explicit_query_scope_hint(raw_query)
        .is_some()
        || crate::agentic::desktop::service::step::queue::web_pipeline::explicit_query_scope_hint(
            normalized_query_contract,
        )
        .is_some();
    let runtime_locality_required = query_requires_runtime_locality_scope(raw_query)
        || (raw_query.is_empty()
            && query_requires_runtime_locality_scope(normalized_query_contract));
    let scalar_measure_required = !query_metric_axes(normalized_query_contract).is_empty();
    let single_fact_snapshot = prefers_single_fact_snapshot(normalized_query_contract)
        || (explicit_entity_cardinality <= 1 && scalar_measure_required && !comparison_required);
    let direct_single_record_snapshot = contract.entity_cardinality_min <= 1
        && contract.structured_record_preferred
        && !contract.comparison_required
        && !contract.ordered_collection_preferred
        && !contract.link_collection_preferred
        && !contract.canonical_link_out_preferred;
    if contract.contract_version.trim().is_empty() {
        contract.contract_version = WEB_RETRIEVAL_CONTRACT_VERSION.to_string();
    }
    contract.entity_cardinality_min = contract
        .entity_cardinality_min
        .clamp(1, 6)
        .max(explicit_entity_cardinality);
    contract.comparison_required = contract.comparison_required || comparison_required;
    contract.currentness_required &= facets.time_sensitive_public_fact;
    contract.runtime_locality_required =
        contract.runtime_locality_required || runtime_locality_required;
    contract.scalar_measure_required = contract.scalar_measure_required || scalar_measure_required;
    contract.source_independence_min = contract.source_independence_min.clamp(1, 6);
    contract.citation_count_min = structural_citation_count_min;

    if contract.entity_cardinality_min <= 1 {
        contract.comparison_required = false;
        contract.ordered_collection_preferred = false;
        contract.link_collection_preferred = false;
        contract.canonical_link_out_preferred = false;
        contract.entity_diversity_required = false;
    }

    if contract.comparison_required || contract.entity_cardinality_min > 1 {
        contract.structured_record_preferred = false;
    }

    if !facets.time_sensitive_public_fact {
        contract.ordered_collection_preferred &=
            query_is_generic_headline_collection(normalized_query_contract);
    }

    if document_briefing_layout && !comparison_required && !contract.runtime_locality_required {
        contract.entity_cardinality_min = 1;
        contract.entity_diversity_required = false;
        contract.comparison_required = false;
        contract.link_collection_preferred = false;
        contract.canonical_link_out_preferred = false;
        contract.ordered_collection_preferred = false;
        contract.discovery_surface_required = true;
        contract.browser_fallback_allowed = false;
    }

    if contract.runtime_locality_required
        && contract.comparison_required
        && contract.entity_cardinality_min > 1
        && !contract.scalar_measure_required
        && !facets.time_sensitive_public_fact
    {
        contract.entity_diversity_required = true;
    }

    if contract.entity_diversity_required {
        contract.entity_cardinality_min = contract.entity_cardinality_min.max(2);
        contract.comparison_required = true;
        contract.link_collection_preferred = true;
        contract.canonical_link_out_preferred = true;
        contract.discovery_surface_required = true;
    }

    if contract.ordered_collection_preferred && contract.entity_diversity_required {
        if contract_requires_geo_scoped_entity_expansion(&contract) {
            contract.ordered_collection_preferred = false;
        } else {
            contract.entity_diversity_required = false;
            contract.link_collection_preferred = false;
            contract.canonical_link_out_preferred = false;
        }
    }

    if direct_single_record_snapshot {
        contract.source_independence_min = 1;
        contract.discovery_surface_required = false;
    } else if contract.entity_diversity_required {
        contract.source_independence_min = contract
            .source_independence_min
            .max(contract.entity_cardinality_min.max(1));
    } else if contract.currentness_required && contract.source_independence_min < 2 {
        contract.source_independence_min = 2;
    }

    if contract.ordered_collection_preferred
        || contract.link_collection_preferred
        || contract.canonical_link_out_preferred
    {
        contract.discovery_surface_required = true;
    }

    if contract.runtime_locality_required
        && (contract.structured_record_preferred || contract.entity_diversity_required)
    {
        contract.geo_scoped_detail_required = true;
    }

    if single_fact_snapshot
        && (scalar_measure_required
            || contract.runtime_locality_required
            || explicit_locality_scope_present)
    {
        contract.structured_record_preferred = true;
    }

    if explicit_locality_scope_present
        && (single_fact_snapshot || contract.entity_diversity_required)
    {
        contract.geo_scoped_detail_required = true;
    }

    if single_fact_snapshot {
        contract.entity_cardinality_min = 1;
        contract.comparison_required = false;
        contract.entity_diversity_required = false;
        contract.link_collection_preferred = false;
        contract.canonical_link_out_preferred = false;
        contract.ordered_collection_preferred = false;
    }

    contract.source_independence_min = structural_source_independence_floor(&contract).clamp(1, 6);
    contract.citation_count_min = structural_citation_count_min;

    if !contract.discovery_surface_required
        && (contract.entity_cardinality_min > 1 || contract.comparison_required)
    {
        return Err(
            "invalid retrieval contract: multi-entity retrieval requires discovery_surface_required=true"
                .to_string(),
        );
    }

    Ok(contract)
}

fn deterministic_web_retrieval_contract(
    query: &str,
    query_contract: Option<&str>,
) -> WebRetrievalContract {
    let structural_query = normalized_query_contract(query, query_contract);
    let facets = analyze_query_facets(structural_query);
    let runtime_locality_required = query_requires_runtime_locality_scope(query.trim())
        || (query.trim().is_empty() && query_requires_runtime_locality_scope(structural_query));
    let comparison_required = query_requests_comparison(structural_query);
    let document_briefing_layout =
        query_prefers_document_briefing_layout(structural_query) && !comparison_required;
    let entity_cardinality_min = if document_briefing_layout {
        1
    } else {
        required_story_count(structural_query).clamp(1, 6) as u32
    };
    let explicit_locality_scope_present =
        crate::agentic::desktop::service::step::queue::web_pipeline::explicit_query_scope_hint(
            query.trim(),
        )
        .is_some()
            || crate::agentic::desktop::service::step::queue::web_pipeline::explicit_query_scope_hint(
                structural_query,
            )
            .is_some();
    let scalar_measure_required =
        entity_cardinality_min <= 1 && !query_metric_axes(structural_query).is_empty();
    let generic_headline_collection = query_is_generic_headline_collection(structural_query);
    let single_fact_snapshot = prefers_single_fact_snapshot(structural_query)
        || (entity_cardinality_min <= 1 && scalar_measure_required && !comparison_required);
    let direct_snapshot_surface_preferred = single_fact_snapshot
        && (scalar_measure_required
            || runtime_locality_required
            || explicit_locality_scope_present);
    let entity_diversity_required = entity_cardinality_min > 1
        && runtime_locality_required
        && !facets.time_sensitive_public_fact
        && !scalar_measure_required;
    let mut contract = WebRetrievalContract {
        contract_version: WEB_RETRIEVAL_CONTRACT_VERSION.to_string(),
        entity_cardinality_min,
        comparison_required,
        currentness_required: facets.time_sensitive_public_fact,
        runtime_locality_required,
        source_independence_min: 1,
        citation_count_min: required_citations_per_story(structural_query).clamp(1, 4) as u32,
        structured_record_preferred: direct_snapshot_surface_preferred,
        ordered_collection_preferred: generic_headline_collection,
        link_collection_preferred: entity_diversity_required,
        canonical_link_out_preferred: entity_diversity_required,
        geo_scoped_detail_required: (runtime_locality_required || explicit_locality_scope_present)
            && (single_fact_snapshot || entity_diversity_required),
        discovery_surface_required: document_briefing_layout
            || generic_headline_collection
            || entity_diversity_required
            || (entity_cardinality_min > 1 && !single_fact_snapshot),
        entity_diversity_required,
        scalar_measure_required,
        browser_fallback_allowed: !document_briefing_layout,
    };
    contract.source_independence_min = structural_source_independence_floor(&contract);
    contract
}

pub fn derive_web_retrieval_contract(
    query: &str,
    query_contract: Option<&str>,
) -> Result<WebRetrievalContract, String> {
    let raw_query = query.trim();
    let normalized_query_contract = normalized_query_contract(query, query_contract);
    if raw_query.is_empty() && normalized_query_contract.is_empty() {
        return Err("web retrieval contract inference requires a non-empty query".to_string());
    }

    lint_web_retrieval_contract(
        query,
        Some(normalized_query_contract),
        deterministic_web_retrieval_contract(raw_query, Some(normalized_query_contract)),
    )
}

pub(crate) fn normalize_web_retrieval_contract(
    query: &str,
    query_contract: Option<&str>,
    contract: WebRetrievalContract,
) -> Result<WebRetrievalContract, String> {
    let raw_query = query.trim();
    let normalized_query_contract = normalized_query_contract(query, query_contract);
    if raw_query.is_empty() && normalized_query_contract.is_empty() {
        return Err("web retrieval contract normalization requires a non-empty query".to_string());
    }

    lint_web_retrieval_contract(query, Some(normalized_query_contract), contract)
}

pub(crate) async fn infer_web_retrieval_contract(
    runtime: Arc<dyn InferenceRuntime>,
    query: &str,
    query_contract: Option<&str>,
) -> Result<WebRetrievalContract, String> {
    let raw_query = query.trim();
    let normalized_query_contract = normalized_query_contract(query, query_contract);
    if raw_query.is_empty() && normalized_query_contract.is_empty() {
        return Err("web retrieval contract inference requires a non-empty query".to_string());
    }

    let prompt = format!(
        concat!(
            "You are classifying a structural web retrieval contract.\n",
            "Return JSON only matching the WebRetrievalContract schema.\n",
            "Use only structural retrieval semantics.\n",
            "Do not emit provider names, domains, or domain-specific affordance labels.\n",
            "Required fields:\n",
            "- contract_version (string; set to \"{version}\")\n",
            "- entity_cardinality_min (integer 1-6)\n",
            "- comparison_required (boolean)\n",
            "- currentness_required (boolean)\n",
            "- runtime_locality_required (boolean)\n",
            "- source_independence_min (integer 1-6)\n",
            "- citation_count_min (integer 1-4)\n",
            "- structured_record_preferred (boolean)\n",
            "- ordered_collection_preferred (boolean)\n",
            "- link_collection_preferred (boolean)\n",
            "- canonical_link_out_preferred (boolean)\n",
            "- geo_scoped_detail_required (boolean)\n",
            "- discovery_surface_required (boolean)\n",
            "- entity_diversity_required (boolean)\n",
            "- scalar_measure_required (boolean)\n",
            "- browser_fallback_allowed (boolean)\n\n",
            "User query:\n{query}\n\n",
            "Resolved query contract:\n{query_contract}\n"
        ),
        version = WEB_RETRIEVAL_CONTRACT_VERSION,
        query = raw_query,
        query_contract = normalized_query_contract,
    );
    let options = InferenceOptions {
        tools: Vec::new(),
        temperature: 0.0,
        json_mode: true,
        max_tokens: 300,
    };
    let raw = runtime
        .execute_inference([0u8; 32], prompt.as_bytes(), options)
        .await
        .map_err(|err| err.to_string())?;
    let response = String::from_utf8(raw).map_err(|err| err.to_string())?;
    let json_object = extract_json_object(&response)
        .ok_or_else(|| "web retrieval contract inference returned non-JSON output".to_string())?;
    let inferred: WebRetrievalContract =
        serde_json::from_str(json_object).map_err(|err| err.to_string())?;
    lint_web_retrieval_contract(query, Some(normalized_query_contract), inferred)
}

pub(crate) fn query_matching_source_urls(
    query_contract: &str,
    retrieval_contract: &WebRetrievalContract,
    sources: &[WebSource],
) -> Result<Vec<String>, String> {
    let normalized_query_contract = query_contract.trim();
    if normalized_query_contract.is_empty() {
        return Err("semantic source alignment requires a non-empty query contract".to_string());
    }
    if sources.is_empty() {
        return Ok(Vec::new());
    }

    let projection = build_query_constraint_projection(
        normalized_query_contract,
        retrieval_contract
            .source_independence_min
            .max(retrieval_contract.entity_cardinality_min.max(1)),
        &[],
    );
    let reject_search_hub = projection.reject_search_hub_candidates();
    let single_snapshot_alignment_required = retrieval_contract.entity_cardinality_min <= 1
        && retrieval_contract.currentness_required
        && !retrieval_contract.comparison_required
        && (retrieval_contract.structured_record_preferred
            || retrieval_contract.geo_scoped_detail_required
            || prefers_single_fact_snapshot(normalized_query_contract));
    let locality_hint = explicit_query_scope_hint(normalized_query_contract);
    let local_business_entity_anchor_required =
        !local_business_search_entity_anchor_tokens_with_contract(
            normalized_query_contract,
            Some(retrieval_contract),
            locality_hint.as_deref(),
        )
        .is_empty();
    let mut ranked = Vec::new();
    let mut seen = std::collections::BTreeSet::new();

    for source in sources.iter().take(WEB_SOURCE_ALIGNMENT_MAX_SOURCES) {
        let candidate_url = semantic_alignment_candidate_url(source);
        let trimmed_url = candidate_url.trim();
        if trimmed_url.is_empty() {
            continue;
        }
        if reject_search_hub && is_search_hub_url(trimmed_url) {
            continue;
        }
        let title = source.title.as_deref().unwrap_or_default();
        let snippet = source.snippet.as_deref().unwrap_or_default();
        if single_snapshot_alignment_required
            && !candidate_time_sensitive_resolvable_payload(trimmed_url, title, snippet)
        {
            continue;
        }
        if local_business_entity_anchor_required
            && !source_matches_local_business_search_entity_anchor(
                normalized_query_contract,
                Some(retrieval_contract),
                locality_hint.as_deref(),
                trimmed_url,
                title,
                snippet,
            )
        {
            continue;
        }
        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed_url,
            title,
            snippet,
        );
        if !compatibility_passes_projection(&projection, &compatibility) {
            continue;
        }
        let normalized = normalize_url_for_id(trimmed_url);
        if !seen.insert(normalized) {
            continue;
        }
        ranked.push((
            compatibility.compatibility_score,
            source.rank.unwrap_or(u32::MAX),
            trimmed_url.to_string(),
        ));
    }

    ranked.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    Ok(ranked.into_iter().map(|(_, _, url)| url).collect())
}

pub(crate) async fn infer_query_matching_source_urls(
    _runtime: Arc<dyn InferenceRuntime>,
    query_contract: &str,
    retrieval_contract: &WebRetrievalContract,
    sources: &[WebSource],
) -> Result<Vec<String>, String> {
    query_matching_source_urls(query_contract, retrieval_contract, sources)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_snapshot_contract() -> WebRetrievalContract {
        WebRetrievalContract {
            contract_version: String::new(),
            entity_cardinality_min: 1,
            comparison_required: false,
            currentness_required: true,
            runtime_locality_required: true,
            source_independence_min: 1,
            citation_count_min: 1,
            structured_record_preferred: true,
            ordered_collection_preferred: false,
            link_collection_preferred: false,
            canonical_link_out_preferred: false,
            geo_scoped_detail_required: true,
            discovery_surface_required: true,
            entity_diversity_required: false,
            scalar_measure_required: true,
            browser_fallback_allowed: true,
        }
    }

    #[test]
    fn lint_normalizes_single_record_snapshot_away_from_discovery_surface() {
        let normalized = lint_web_retrieval_contract(
            "What's the weather like right now near me?",
            Some("What's the weather like right now in Anderson, SC?"),
            direct_snapshot_contract(),
        )
        .expect("contract should lint");

        assert_eq!(normalized.contract_version, WEB_RETRIEVAL_CONTRACT_VERSION);
        assert_eq!(normalized.source_independence_min, 1);
        assert!(
            !normalized.discovery_surface_required,
            "single-record structured snapshots should not force discovery surfaces"
        );
    }

    #[test]
    fn lint_demotes_non_geo_entity_expansion_when_ordered_collection_is_requested() {
        let mut contract = direct_snapshot_contract();
        contract.entity_cardinality_min = 5;
        contract.comparison_required = true;
        contract.currentness_required = true;
        contract.runtime_locality_required = false;
        contract.structured_record_preferred = false;
        contract.ordered_collection_preferred = true;
        contract.link_collection_preferred = true;
        contract.canonical_link_out_preferred = true;
        contract.discovery_surface_required = true;
        contract.entity_diversity_required = true;

        let normalized = lint_web_retrieval_contract(
            "Top headlines today",
            Some("Top headlines today"),
            contract,
        )
        .expect("contract should lint");

        assert!(normalized.ordered_collection_preferred);
        assert!(!normalized.entity_diversity_required);
        assert!(!normalized.link_collection_preferred);
        assert!(!normalized.canonical_link_out_preferred);
    }

    #[test]
    fn lint_preserves_geo_scoped_entity_expansion_over_ordered_collection() {
        let mut contract = direct_snapshot_contract();
        contract.entity_cardinality_min = 3;
        contract.comparison_required = true;
        contract.currentness_required = false;
        contract.runtime_locality_required = true;
        contract.structured_record_preferred = false;
        contract.ordered_collection_preferred = true;
        contract.link_collection_preferred = true;
        contract.canonical_link_out_preferred = true;
        contract.discovery_surface_required = true;
        contract.geo_scoped_detail_required = true;
        contract.entity_diversity_required = true;

        let normalized = lint_web_retrieval_contract(
            "Find the three best-reviewed Italian restaurants near me and compare their menus.",
            Some("Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."),
            contract,
        )
        .expect("contract should lint");

        assert!(!normalized.ordered_collection_preferred);
        assert!(normalized.entity_diversity_required);
        assert!(normalized.link_collection_preferred);
        assert!(normalized.canonical_link_out_preferred);
    }

    #[test]
    fn lint_demotes_document_briefing_comparison_scaffolding_without_explicit_compare() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = WebRetrievalContract {
            contract_version: WEB_RETRIEVAL_CONTRACT_VERSION.to_string(),
            entity_cardinality_min: 3,
            comparison_required: true,
            currentness_required: true,
            runtime_locality_required: false,
            source_independence_min: 3,
            citation_count_min: 1,
            structured_record_preferred: false,
            ordered_collection_preferred: false,
            link_collection_preferred: true,
            canonical_link_out_preferred: true,
            geo_scoped_detail_required: false,
            discovery_surface_required: true,
            entity_diversity_required: true,
            scalar_measure_required: false,
            browser_fallback_allowed: true,
        };

        let normalized = lint_web_retrieval_contract(query, Some(query), contract)
            .expect("contract should lint");

        assert_eq!(normalized.entity_cardinality_min, 1);
        assert_eq!(normalized.source_independence_min, 2);
        assert!(!normalized.comparison_required);
        assert!(!normalized.entity_diversity_required);
        assert!(!normalized.link_collection_preferred);
        assert!(!normalized.canonical_link_out_preferred);
        assert!(!normalized.ordered_collection_preferred);
        assert!(normalized.discovery_surface_required);
    }

    #[test]
    fn semantic_alignment_requirement_tracks_subject_sensitive_contracts() {
        let mut contract = direct_snapshot_contract();
        contract.scalar_measure_required = false;
        contract.currentness_required = false;
        contract.source_independence_min = 1;
        assert!(!contract_requires_semantic_source_alignment(&contract));

        contract.scalar_measure_required = true;
        assert!(contract_requires_semantic_source_alignment(&contract));

        contract.scalar_measure_required = false;
        contract.entity_diversity_required = true;
        assert!(contract_requires_semantic_source_alignment(&contract));
    }

    #[test]
    fn semantic_alignment_requirement_skips_generic_ordered_collections() {
        let mut contract = direct_snapshot_contract();
        contract.entity_cardinality_min = 5;
        contract.currentness_required = true;
        contract.source_independence_min = 5;
        contract.scalar_measure_required = false;
        contract.ordered_collection_preferred = true;
        contract.discovery_surface_required = true;
        contract.structured_record_preferred = false;

        assert!(!contract_requires_semantic_source_alignment(&contract));

        contract.scalar_measure_required = true;
        assert!(contract_requires_semantic_source_alignment(&contract));
    }

    #[test]
    fn deterministic_contract_prefers_direct_snapshot_surfaces_for_local_current_snapshot_queries()
    {
        let contract = deterministic_web_retrieval_contract(
            "What's the weather like right now near me?",
            Some("What's the weather like right now in Anderson, SC?"),
        );

        assert_eq!(contract.entity_cardinality_min, 1);
        assert!(contract.currentness_required);
        assert!(contract.runtime_locality_required);
        assert!(contract.structured_record_preferred);
        assert!(contract.geo_scoped_detail_required);
        assert!(!contract.ordered_collection_preferred);
        assert!(!contract.discovery_surface_required);
    }

    #[test]
    fn deterministic_contract_prefers_direct_snapshot_surfaces_for_explicit_local_weather_queries()
    {
        let contract = deterministic_web_retrieval_contract(
            "What's the weather like right now in Anderson, SC?",
            Some("What's the weather like right now in Anderson, SC?"),
        );

        assert_eq!(contract.entity_cardinality_min, 1);
        assert!(contract.currentness_required);
        assert!(!contract.runtime_locality_required);
        assert!(contract.structured_record_preferred);
        assert!(contract.geo_scoped_detail_required);
        assert!(!contract.ordered_collection_preferred);
        assert!(!contract.discovery_surface_required);
    }

    #[test]
    fn semantic_alignment_rejects_weather_news_for_local_current_snapshot_queries() {
        let contract = deterministic_web_retrieval_contract(
            "What's the weather like right now near me?",
            Some("What's the weather like right now in Anderson, SC?"),
        );
        let sources = vec![
            WebSource {
                source_id: "weather-news".to_string(),
                rank: Some(1),
                url: "https://example.com/weather/advisory-story".to_string(),
                title: Some("Winter weather advisory expands across the Upstate".to_string()),
                snippet: Some(
                    "Anderson County remains under a weather advisory overnight as a cold front moves through."
                        .to_string(),
                ),
                domain: Some("example.com".to_string()),
            },
            WebSource {
                source_id: "weather-record".to_string(),
                rank: Some(2),
                url: "https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC"
                    .to_string(),
                title: Some("Anderson, SC current conditions".to_string()),
                snippet: Some(
                    "Current conditions: temperature 62 F, humidity 42%, wind 4 mph, observed at 2:00 PM."
                        .to_string(),
                ),
                domain: Some("forecast.weather.gov".to_string()),
            },
        ];

        let aligned = query_matching_source_urls(
            "What's the weather like right now in Anderson, SC?",
            &contract,
            &sources,
        )
        .expect("alignment should succeed");

        assert_eq!(
            aligned,
            vec!["https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC"]
        );
    }

    #[test]
    fn derived_contract_marks_latest_plural_briefing_queries_as_document_briefings() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");

        assert_eq!(contract.entity_cardinality_min, 1);
        assert_eq!(contract.source_independence_min, 2);
        assert_eq!(contract.citation_count_min, 1);
        assert!(contract.currentness_required);
        assert!(!contract.comparison_required);
        assert!(!contract.structured_record_preferred);
        assert!(!contract.ordered_collection_preferred);
        assert!(!contract.entity_diversity_required);
        assert!(contract.discovery_surface_required);
        assert!(!contract.browser_fallback_allowed);
    }

    #[test]
    fn derived_contract_preserves_document_briefing_shape_when_query_contract_is_present() {
        let query = "nist post quantum cryptography standards";
        let query_contract =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract =
            derive_web_retrieval_contract(query, Some(query_contract)).expect("contract");

        assert_eq!(contract.entity_cardinality_min, 1);
        assert_eq!(contract.source_independence_min, 2);
        assert!(contract.currentness_required);
        assert!(!contract.structured_record_preferred);
        assert!(contract.discovery_surface_required);
        assert!(!contract.browser_fallback_allowed);
    }

    #[test]
    fn normalized_contract_restores_runtime_locality_for_scope_resolved_restaurant_query() {
        let query =
            "Find the three best-reviewed Italian restaurants near me and compare their menus.";
        let query_contract =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let incoming = WebRetrievalContract {
            contract_version: WEB_RETRIEVAL_CONTRACT_VERSION.to_string(),
            entity_cardinality_min: 3,
            comparison_required: true,
            currentness_required: false,
            runtime_locality_required: false,
            source_independence_min: 3,
            citation_count_min: 1,
            structured_record_preferred: false,
            ordered_collection_preferred: false,
            link_collection_preferred: false,
            canonical_link_out_preferred: false,
            geo_scoped_detail_required: false,
            discovery_surface_required: true,
            entity_diversity_required: false,
            scalar_measure_required: false,
            browser_fallback_allowed: true,
        };

        let normalized = normalize_web_retrieval_contract(query, Some(query_contract), incoming)
            .expect("contract should normalize");

        assert_eq!(normalized.entity_cardinality_min, 3);
        assert!(normalized.comparison_required);
        assert!(normalized.runtime_locality_required);
        assert!(normalized.geo_scoped_detail_required);
        assert!(normalized.entity_diversity_required);
        assert!(normalized.link_collection_preferred);
        assert!(normalized.canonical_link_out_preferred);
        assert!(normalized.discovery_surface_required);
        assert_eq!(normalized.source_independence_min, 3);
    }

    #[test]
    fn semantic_alignment_accepts_geo_scoped_restaurant_directory_category_sources() {
        let query =
            "Find the three best-reviewed Italian restaurants near me and compare their menus.";
        let query_contract =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let contract =
            derive_web_retrieval_contract(query, Some(query_contract)).expect("contract");
        let sources = vec![WebSource {
            source_id: "restaurantji-italian".to_string(),
            rank: Some(1),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            title: Some("Italian".to_string()),
            snippet: Some(
                "Find the best places to eat in Anderson, SC with menus, reviews and photos."
                    .to_string(),
            ),
            domain: Some("restaurantji.com".to_string()),
        }];

        let aligned =
            query_matching_source_urls(query_contract, &contract, &sources).expect("alignment");

        assert_eq!(
            aligned,
            vec!["https://www.restaurantji.com/sc/anderson/italian/"]
        );
    }

    #[test]
    fn semantic_alignment_rejects_wrong_cuisine_local_business_sources() {
        let query =
            "Find the three best-reviewed Italian restaurants near me and compare their menus.";
        let query_contract =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let contract =
            derive_web_retrieval_contract(query, Some(query_contract)).expect("contract");
        let sources = vec![
            WebSource {
                source_id: "restaurantji-fast-food".to_string(),
                rank: Some(1),
                url: "https://www.restaurantji.com/sc/anderson/fast-food/".to_string(),
                title: Some("Fast Food".to_string()),
                snippet: Some(
                    "Find the best places to eat in Anderson, SC with menus, reviews and photos."
                        .to_string(),
                ),
                domain: Some("restaurantji.com".to_string()),
            },
            WebSource {
                source_id: "restaurantji-american".to_string(),
                rank: Some(2),
                url: "https://www.restaurantji.com/sc/anderson/american/".to_string(),
                title: Some("American".to_string()),
                snippet: Some(
                    "Find the best places to eat in Anderson, SC with menus, reviews and photos."
                        .to_string(),
                ),
                domain: Some("restaurantji.com".to_string()),
            },
        ];

        let aligned =
            query_matching_source_urls(query_contract, &contract, &sources).expect("alignment");

        assert!(aligned.is_empty());
    }

    #[test]
    fn semantic_alignment_accepts_representative_nist_pqc_briefing_sources() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");
        let sources = vec![
            WebSource {
                source_id: "nist-finalized".to_string(),
                rank: Some(1),
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST releases first 3 finalized post-quantum encryption standards"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                        .to_string(),
                ),
                domain: Some("nist.gov".to_string()),
            },
            WebSource {
                source_id: "ibm-summary".to_string(),
                rank: Some(2),
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some("NIST’s post-quantum cryptography standards are here".to_string()),
                snippet: Some(
                    "IBM summarized the NIST post-quantum standards ML-KEM, ML-DSA and SLH-DSA."
                        .to_string(),
                ),
                domain: Some("research.ibm.com".to_string()),
            },
            WebSource {
                source_id: "nist-hqc".to_string(),
                rank: Some(3),
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST selects HQC as fifth algorithm for post-quantum encryption".to_string(),
                ),
                snippet: Some(
                    "NIST selected HQC as a backup algorithm in the post-quantum cryptography standards effort."
                        .to_string(),
                ),
                domain: Some("nist.gov".to_string()),
            },
        ];

        let aligned =
            query_matching_source_urls(query, &contract, &sources).expect("alignment should work");

        assert_eq!(aligned.len(), 3, "aligned_urls={aligned:?}");
        assert!(aligned
            .iter()
            .any(|url| url.contains("finalized-post-quantum-encryption-standards")));
        assert!(aligned
            .iter()
            .any(|url| url.contains("research.ibm.com/blog/nist-pqc-standards")));
        assert!(aligned
            .iter()
            .any(|url| url.contains("nist-selects-hqc-fifth-algorithm")));
    }

    #[test]
    fn semantic_alignment_resolves_google_news_wrappers_to_canonical_source_urls() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");
        let sources = vec![WebSource {
            source_id: "google-wrapper".to_string(),
            rank: Some(1),
            url: "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string(),
            title: Some(
                "NIST releases first 3 finalized post-quantum encryption standards".to_string(),
            ),
            snippet: Some(
                "Google News | source_url=https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            ),
            domain: Some("news.google.com".to_string()),
        }];

        let aligned =
            query_matching_source_urls(query, &contract, &sources).expect("alignment should work");

        assert_eq!(
            aligned,
            vec![
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            ]
        );
    }
}
