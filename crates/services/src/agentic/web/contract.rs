use ioi_api::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::{InferenceOptions, WebRetrievalContract, WebSource};
use serde::Serialize;
use std::sync::Arc;

use super::util::normalize_url_for_id;
use crate::agentic::runtime::service::step::queue::web_pipeline::{
    build_query_constraint_projection, candidate_constraint_compatibility,
    candidate_time_sensitive_resolvable_payload, compatibility_passes_projection,
    explicit_query_scope_hint, is_search_hub_url,
    local_business_search_entity_anchor_tokens_with_contract, prefers_single_fact_snapshot,
    query_is_generic_headline_collection, query_metric_axes,
    query_prefers_document_briefing_layout, query_requests_comparison,
    query_requires_runtime_locality_scope, required_citations_per_story, required_story_count,
    retrieval_contract_min_sources, source_has_document_briefing_authority_alignment_with_contract,
    source_matches_local_business_search_entity_anchor,
};
use crate::agentic::runtime::service::step::signals::analyze_query_facets;

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
    if !is_search_hub_url(trimmed)
        && !crate::agentic::web::is_google_news_article_wrapper_url(trimmed)
    {
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
    let explicit_locality_scope_present = crate::agentic::runtime::service::step::queue::web_pipeline::explicit_query_scope_hint(raw_query)
        .is_some()
        || crate::agentic::runtime::service::step::queue::web_pipeline::explicit_query_scope_hint(
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

    if (contract.runtime_locality_required || explicit_locality_scope_present)
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

    if single_fact_snapshot {
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
        crate::agentic::runtime::service::step::queue::web_pipeline::explicit_query_scope_hint(
            query.trim(),
        )
        .is_some()
            || crate::agentic::runtime::service::step::queue::web_pipeline::explicit_query_scope_hint(
                structural_query,
            )
            .is_some();
    let scalar_measure_required =
        entity_cardinality_min <= 1 && !query_metric_axes(structural_query).is_empty();
    let generic_headline_collection = query_is_generic_headline_collection(structural_query);
    let single_fact_snapshot = prefers_single_fact_snapshot(structural_query)
        || (entity_cardinality_min <= 1 && scalar_measure_required && !comparison_required);
    let direct_snapshot_surface_preferred = single_fact_snapshot;
    let entity_diversity_required = entity_cardinality_min > 1
        && (runtime_locality_required || explicit_locality_scope_present)
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
        stop_sequences: Vec::new(),
        required_finality_tier: Default::default(),
        sealed_finality_proof: None,
        canonical_collapse_object: None,
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
    let grounding_min_sources =
        retrieval_contract_min_sources(Some(retrieval_contract), normalized_query_contract)
            as usize;
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
        let authority_aligned = source_has_document_briefing_authority_alignment_with_contract(
            Some(retrieval_contract),
            normalized_query_contract,
            grounding_min_sources,
            trimmed_url,
            title,
            snippet,
        );
        if !compatibility_passes_projection(&projection, &compatibility) && !authority_aligned {
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
#[path = "contract/tests.rs"]
mod tests;
