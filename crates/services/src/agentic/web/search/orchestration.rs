use super::profile::provider_supports_affordance;
use super::super::parsers::{
    fetch_bing_news_rss_sources, fetch_bing_search_rss_sources, fetch_google_news_rss_sources,
    fetch_google_news_top_stories_rss_sources, parse_bing_sources_from_html,
    parse_brave_sources_from_html, parse_ddg_sources_from_html, parse_generic_page_source_from_html,
    parse_google_sources_from_html,
};
use super::super::readability::{extract_non_html_read_blocks, extract_read_blocks};
use super::super::transport::{
    detect_human_challenge, fetch_html_http_fallback_browser_ua,
    fetch_structured_detail_http_fallback_browser_ua,
    fetch_structured_detail_http_fallback_browser_ua_with_final_url, navigate_browser_retrieval,
};
use super::super::types::{SearchProviderStage, SearchStructuralAffordance};
use super::super::urls::{
    build_bing_news_rss_url, build_bing_search_rss_url, build_bing_serp_url,
    build_brave_serp_url, build_ddg_serp_url, build_google_news_rss_url,
    build_google_news_serp_url, build_google_news_top_stories_rss_url, build_google_serp_url,
    build_weather_gov_locality_lookup_url,
};
use super::super::util::{compact_ws, domain_for_url, normalize_url_for_id, now_ms, source_id_for_url};
use super::{
    extraction::*,
    profile::{
        provider_backend_id, provider_candidate_is_usable, provider_candidate_selection_key,
        provider_descriptor_is_admissible, provider_probe_priority_key, search_budget_exhausted,
        search_provider_registry, search_provider_requirements_from_contract,
        SearchProviderCandidateSelectionInput, SearchProviderDescriptor,
    },
};
use crate::agentic::desktop::service::step::queue::web_pipeline::{
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint,
    effective_locality_scope_hint, explicit_query_scope_hint, retrieval_contract_min_sources,
};
use crate::agentic::web::{
    contract_requires_geo_scoped_entity_expansion, contract_requires_semantic_source_alignment,
    query_matching_source_urls, WEB_SOURCE_ALIGNMENT_MAX_SOURCES,
};
use crate::agentic::web::constants::EDGE_WEB_SEARCH_TOTAL_BUDGET_MS;
use anyhow::Result;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::{
    WebEvidenceBundle, WebProviderCandidate, WebSource, WebSourceExpansionAffordance,
    WebSourceObservation,
};
use crate::agentic::desktop::service::step::signals::analyze_metric_schema;
use ioi_types::app::agentic::WebRetrievalContract;
use std::collections::HashSet;

fn best_metric_excerpt(blocks: &[String]) -> Option<String> {
    blocks
        .iter()
        .filter_map(|block| {
            let compact = compact_ws(block);
            let trimmed = compact.trim();
            if trimmed.is_empty() {
                return None;
            }
            let schema = analyze_metric_schema(trimmed);
            let score = usize::from(schema.has_current_observation_payload()) * 8
                + schema.axis_hits.len() * 4
                + schema.timestamp_hits
                + schema.unit_hits
                + schema.numeric_token_hits;
            (score > 0).then(|| (score, trimmed.to_string()))
        })
        .max_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| right.1.len().cmp(&left.1.len()))
        })
        .map(|(_, block)| block)
}

fn best_structured_detail_source(
    page_url: &str,
    html: &str,
    extracted_title: Option<String>,
    blocks: &[String],
) -> Option<WebSource> {
    let generic_page = parse_generic_page_source_from_html(page_url, html);
    let title = extracted_title
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            generic_page
                .as_ref()
                .and_then(|source| source.title.clone())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        });
    let snippet = best_metric_excerpt(blocks).or_else(|| {
        generic_page
            .as_ref()
            .and_then(|source| source.snippet.clone())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    });
    if title.is_none() && snippet.is_none() {
        return None;
    }

    Some(WebSource {
        source_id: source_id_for_url(page_url),
        rank: Some(1),
        domain: domain_for_url(page_url),
        title,
        snippet,
        url: page_url.to_string(),
    })
}

fn reliability_fixture_sources() -> Option<Vec<String>> {
    let raw = std::env::var("IOI_RELIABILITY_WEB_SEARCH_FIXTURE_URLS").ok()?;
    let urls = raw
        .split(',')
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect::<Vec<_>>();
    if urls.is_empty() {
        None
    } else {
        Some(urls)
    }
}

fn excluded_hosts_from_query(query: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for token in query.split_whitespace() {
        let normalized = token
            .trim_matches(|ch: char| matches!(ch, ',' | ';' | ')' | '(' | '"' | '\''))
            .to_ascii_lowercase();
        let Some(host_raw) = normalized.strip_prefix("-site:") else {
            continue;
        };
        let host = host_raw
            .trim()
            .trim_start_matches("www.")
            .trim_end_matches('.');
        if host.is_empty() {
            continue;
        }
        out.insert(host.to_string());
    }
    out
}

fn source_matches_excluded_host(source: &WebSource, excluded_hosts: &HashSet<String>) -> bool {
    if excluded_hosts.is_empty() {
        return false;
    }
    canonical_source_domain(source)
        .map(|domain| {
            excluded_hosts
                .iter()
                .any(|excluded| domain == *excluded || domain.ends_with(&format!(".{}", excluded)))
        })
        .unwrap_or(false)
}

fn append_unique_sources(existing: &mut Vec<WebSource>, incoming: Vec<WebSource>) {
    let mut seen = existing
        .iter()
        .map(|source| normalize_url_for_id(&source.url))
        .collect::<HashSet<_>>();
    for source in incoming {
        let key = normalize_url_for_id(&source.url);
        if seen.insert(key) {
            existing.push(source);
        }
    }
}

fn append_unique_source_observations(
    existing: &mut Vec<WebSourceObservation>,
    incoming: Vec<WebSourceObservation>,
) {
    let mut seen = existing
        .iter()
        .map(|source| normalize_url_for_id(&source.url))
        .collect::<HashSet<_>>();
    for source in incoming {
        let key = normalize_url_for_id(&source.url);
        if seen.insert(key) {
            existing.push(source);
        }
    }
}

fn source_observations_for_sources(
    sources: &[WebSource],
    affordances: &[SearchStructuralAffordance],
    expansion_affordances: &[WebSourceExpansionAffordance],
) -> Vec<WebSourceObservation> {
    sources
        .iter()
        .map(|source| WebSourceObservation {
            url: source.url.clone(),
            affordances: affordances.to_vec(),
            expansion_affordances: expansion_affordances.to_vec(),
        })
        .collect()
}

fn reorder_headline_sources_for_truncation(sources: Vec<WebSource>) -> Vec<WebSource> {
    if sources.is_empty() {
        return sources;
    }

    let mut ranked = sources;
    ranked.sort_by(|left, right| {
        let left_domain_known = canonical_source_domain(left).is_some();
        let right_domain_known = canonical_source_domain(right).is_some();
        right_domain_known
            .cmp(&left_domain_known)
            .then_with(|| {
                left.rank
                    .unwrap_or(u32::MAX)
                    .cmp(&right.rank.unwrap_or(u32::MAX))
            })
            .then_with(|| left.url.cmp(&right.url))
    });

    let mut reordered = Vec::with_capacity(ranked.len());
    let mut seen_urls = HashSet::new();
    let mut seen_domains = HashSet::new();

    for source in ranked.iter().filter(|source| canonical_source_domain(source).is_some()) {
        let url_key = normalize_url_for_id(&source.url);
        let Some(domain_key) = canonical_source_domain(source) else {
            continue;
        };
        if !seen_urls.insert(url_key) || !seen_domains.insert(domain_key) {
            continue;
        }
        reordered.push(source.clone());
    }
    for source in ranked {
        let url_key = normalize_url_for_id(&source.url);
        if seen_urls.insert(url_key) {
            reordered.push(source);
        }
    }

    reordered
}

pub(crate) fn aggregated_sources_meet_pre_read_floor(
    retrieval_contract: &WebRetrievalContract,
    query_contract: &str,
    _locality_hint: Option<&str>,
    _discovery_inventory_limit: usize,
    sources: &[WebSource],
) -> bool {
    if sources.is_empty() {
        return false;
    }

    let required_url_count =
        retrieval_contract_min_sources(Some(retrieval_contract), query_contract).max(1);
    let required_source_count = required_url_count as usize;
    let required_domain_floor = if retrieval_contract.entity_diversity_required {
        0
    } else {
        retrieval_contract
            .source_independence_min
            .max(1)
            .min(required_url_count) as usize
    };
    let mut distinct_urls = HashSet::new();
    let mut distinct_domains = HashSet::new();
    for source in sources {
        let trimmed = source.url.trim();
        if trimmed.is_empty() {
            continue;
        }
        if distinct_urls.insert(normalize_url_for_id(trimmed)) {
            if let Some(domain) = canonical_source_domain(source) {
                distinct_domains.insert(domain);
            }
        }
    }
    distinct_urls.len() >= required_source_count
        && (required_domain_floor == 0 || distinct_domains.len() >= required_domain_floor)
}

fn direct_single_record_snapshot_contract(retrieval_contract: &WebRetrievalContract) -> bool {
    retrieval_contract.entity_cardinality_min <= 1
        && retrieval_contract.structured_record_preferred
        && !retrieval_contract.comparison_required
        && !retrieval_contract.ordered_collection_preferred
        && !retrieval_contract.link_collection_preferred
        && !retrieval_contract.canonical_link_out_preferred
        && !retrieval_contract.discovery_surface_required
}

fn descriptor_supports_direct_snapshot_record(descriptor: &SearchProviderDescriptor) -> bool {
    provider_supports_affordance(descriptor, SearchStructuralAffordance::StructuredRecord)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::GeoScopedRecord)
        || provider_supports_affordance(descriptor, SearchStructuralAffordance::DetailDocument)
}

pub(crate) fn should_stop_provider_aggregation(
    retrieval_contract: &WebRetrievalContract,
    query_contract: &str,
    locality_hint: Option<&str>,
    discovery_inventory_limit: usize,
    provider_result_limit: usize,
    aggregated_sources: &[WebSource],
    last_descriptor: Option<&SearchProviderDescriptor>,
    preferred_only_mode: bool,
) -> bool {
    let floor_met = aggregated_sources_meet_pre_read_floor(
        retrieval_contract,
        query_contract,
        locality_hint,
        discovery_inventory_limit,
        aggregated_sources,
    );
    if !floor_met {
        return false;
    }

    if preferred_only_mode && aggregated_sources.len() >= provider_result_limit {
        return true;
    }

    direct_single_record_snapshot_contract(retrieval_contract)
        && last_descriptor
            .map(descriptor_supports_direct_snapshot_record)
            .unwrap_or(false)
}

fn resolved_locality_scope(
    query: &str,
    query_contract: Option<&str>,
    retrieval_contract: &WebRetrievalContract,
) -> Option<String> {
    let query_contract = query_contract
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let query = query.trim();
    query_contract
        .and_then(explicit_query_scope_hint)
        .or_else(|| explicit_query_scope_hint(query))
        .or_else(|| {
            retrieval_contract
                .runtime_locality_required
                .then(|| effective_locality_scope_hint(None))
                .flatten()
        })
}

fn provider_request_query(
    query: &str,
    query_contract: Option<&str>,
    retrieval_contract: &WebRetrievalContract,
    locality_scope: Option<&str>,
) -> String {
    let selection_query_contract = query_contract
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| query.trim());
    let discovery_query_basis = if contract_requires_geo_scoped_entity_expansion(retrieval_contract)
        || (retrieval_contract.discovery_surface_required
            && retrieval_contract.link_collection_preferred
            && retrieval_contract.entity_cardinality_min > 1)
    {
        query.trim()
    } else {
        selection_query_contract
    };
    let grounded_query =
        constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            discovery_query_basis,
            Some(retrieval_contract),
            retrieval_contract_min_sources(Some(retrieval_contract), selection_query_contract)
                .max(1),
            &[],
            locality_scope,
        );
    let grounded_trimmed = grounded_query.trim();
    if !grounded_trimmed.is_empty() {
        return grounded_trimmed.to_string();
    }

    provider_search_query_with_locality_hint(discovery_query_basis, locality_scope)
}

#[derive(Debug, Clone)]
struct ObservedSearchProviderCandidate {
    descriptor: SearchProviderDescriptor,
    request_url: Option<String>,
    sources: Vec<WebSource>,
    source_observations: Vec<WebSourceObservation>,
    success: bool,
    selected: bool,
    challenge_reason: Option<String>,
    fallback_note: Option<String>,
}

impl ObservedSearchProviderCandidate {
    fn selection_input(&self) -> SearchProviderCandidateSelectionInput<'_> {
        SearchProviderCandidateSelectionInput {
            descriptor: &self.descriptor,
            source_count: self.sources.len(),
            challenge_present: self.challenge_reason.is_some(),
        }
    }

    fn bundle_candidate(&self) -> WebProviderCandidate {
        WebProviderCandidate {
            provider_id: provider_backend_id(self.descriptor.stage).to_string(),
            affordances: self.descriptor.affordances.to_vec(),
            request_url: self.request_url.clone(),
            source_count: self.sources.len() as u32,
            success: self.success,
            selected: self.selected,
            challenge_reason: self.challenge_reason.clone(),
        }
    }
}

fn finalize_provider_sources(
    sources: Vec<WebSource>,
    excluded_hosts: &HashSet<String>,
) -> Vec<WebSource> {
    let mut filtered_sources = sources;
    if !excluded_hosts.is_empty() {
        filtered_sources.retain(|source| !source_matches_excluded_host(source, excluded_hosts));
    }
    filtered_sources
}

fn filter_provider_sources_by_contract(
    sources: Vec<WebSource>,
    query_contract: &str,
    retrieval_contract: &WebRetrievalContract,
) -> Vec<WebSource> {
    if !contract_requires_semantic_source_alignment(retrieval_contract) {
        return sources;
    }

    let aligned_urls = match query_matching_source_urls(query_contract, retrieval_contract, &sources)
    {
        Ok(urls) => urls,
        Err(_) => return Vec::new(),
    };
    if aligned_urls.is_empty() {
        return Vec::new();
    }
    let aligned_keys = aligned_urls
        .into_iter()
        .map(|url| normalize_url_for_id(&url))
        .collect::<HashSet<_>>();
    sources
        .into_iter()
        .filter(|source| aligned_keys.contains(&normalize_url_for_id(&source.url)))
        .collect()
}

async fn probe_search_provider(
    browser: &BrowserDriver,
    descriptor: SearchProviderDescriptor,
    query_for_provider: &str,
    query_contract: &str,
    retrieval_contract: &WebRetrievalContract,
    locality_scope: Option<&str>,
    headline_lookup_mode: bool,
    provider_result_limit: usize,
    _expansion_surface_preferred: bool,
    excluded_hosts: &HashSet<String>,
) -> ObservedSearchProviderCandidate {
    let provider_id = provider_backend_id(descriptor.stage);
    let fallback = |fallback_note: Option<String>,
                    request_url: Option<String>,
                    challenge_reason: Option<String>,
                    success: bool| ObservedSearchProviderCandidate {
        descriptor,
        request_url,
        sources: Vec::new(),
        source_observations: Vec::new(),
        success,
        selected: false,
        challenge_reason,
        fallback_note,
    };
    match descriptor.stage {
        SearchProviderStage::WeatherGovLocalityDetail => {
            let Some(scope) = locality_scope.map(str::trim).filter(|value| !value.is_empty()) else {
                return fallback(
                    Some(format!("{}_locality_scope_missing", provider_id)),
                    None,
                    None,
                    false,
                );
            };
            let request_url = build_weather_gov_locality_lookup_url(scope);
            match fetch_structured_detail_http_fallback_browser_ua_with_final_url(&request_url).await
            {
                Ok((final_url, html)) => {
                    let challenge_reason = detect_human_challenge(&final_url, &html)
                        .or_else(|| detect_human_challenge(&request_url, &html))
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let (extracted_title, mut blocks) = extract_read_blocks(&html);
                    if blocks.is_empty() {
                        blocks = extract_non_html_read_blocks(&html);
                    }
                    let sources = best_structured_detail_source(
                        &final_url,
                        &html,
                        extracted_title,
                        &blocks,
                    )
                    .into_iter()
                    .collect::<Vec<_>>();
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    let source_observations = source_observations_for_sources(
                        &sources,
                        descriptor.affordances,
                        &[],
                    );
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations,
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::BraveHttp => {
            let request_url = build_brave_serp_url(query_for_provider);
            match fetch_structured_detail_http_fallback_browser_ua(&request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_brave_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::DdgHttp => {
            let request_url = build_ddg_serp_url(query_for_provider);
            match fetch_html_http_fallback_browser_ua(&request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_ddg_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::DdgBrowser => {
            let request_url = build_ddg_serp_url(query_for_provider);
            match navigate_browser_retrieval(browser, &request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_ddg_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::BingHttp => {
            let request_url = build_bing_serp_url(query_for_provider);
            match fetch_html_http_fallback_browser_ua(&request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_bing_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::BingNewsRss => {
            let request_url = build_bing_news_rss_url(query_for_provider);
            match fetch_bing_news_rss_sources(query_for_provider, provider_result_limit).await {
                Ok(sources) => {
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::BingSearchRss => {
            let request_url = build_bing_search_rss_url(query_for_provider);
            match fetch_bing_search_rss_sources(query_for_provider, provider_result_limit).await {
                Ok(sources) => {
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::GoogleHttp => {
            let request_url = if headline_lookup_mode {
                build_google_news_serp_url(query_for_provider)
            } else {
                build_google_serp_url(query_for_provider)
            };
            match fetch_html_http_fallback_browser_ua(&request_url).await {
                Ok(html) => {
                    let challenge_reason = detect_human_challenge(&request_url, &html)
                        .map(|reason| reason.to_string());
                    if let Some(reason) = challenge_reason.clone() {
                        return fallback(
                            Some(format!("{}_challenge={}", provider_id, reason)),
                            Some(request_url),
                            Some(reason),
                            true,
                        );
                    }

                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(
                            parse_google_sources_from_html(&html, provider_result_limit),
                            excluded_hosts,
                        ),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::GoogleNewsRss => {
            let request_url = build_google_news_rss_url(query_for_provider);
            match fetch_google_news_rss_sources(query_for_provider, provider_result_limit).await {
                Ok(sources) => {
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
        SearchProviderStage::GoogleNewsTopStoriesRss => {
            let request_url = build_google_news_top_stories_rss_url();
            match fetch_google_news_top_stories_rss_sources(provider_result_limit).await {
                Ok(sources) => {
                    let sources = filter_provider_sources_by_contract(
                        finalize_provider_sources(sources, excluded_hosts),
                        query_contract,
                        retrieval_contract,
                    );
                    let fallback_note = if sources.is_empty() {
                        Some(format!("{}_empty", provider_id))
                    } else {
                        None
                    };
                    ObservedSearchProviderCandidate {
                        descriptor,
                        request_url: Some(request_url),
                        sources,
                        source_observations: Vec::new(),
                        success: true,
                        selected: false,
                        challenge_reason: None,
                        fallback_note,
                    }
                }
                Err(err) => fallback(
                    Some(format!("{}_error={}", provider_id, err)),
                    Some(request_url),
                    None,
                    false,
                ),
            }
        }
    }
}

pub async fn edge_web_search(
    browser: &BrowserDriver,
    query: &str,
    query_contract: Option<&str>,
    retrieval_contract: &WebRetrievalContract,
    limit: u32,
) -> Result<WebEvidenceBundle> {
    if let Some(fixture_urls) = reliability_fixture_sources() {
        let effective_limit = limit.max(1) as usize;
        let sources = fixture_urls
            .into_iter()
            .take(effective_limit)
            .enumerate()
            .map(|(idx, url)| WebSource {
                source_id: source_id_for_url(&url),
                rank: Some((idx + 1) as u32),
                domain: domain_for_url(&url),
                title: Some(format!("Reliability Fixture Source {}", idx + 1)),
                snippet: Some("Deterministic search fixture source".to_string()),
                url,
            })
            .collect::<Vec<_>>();

        let source_url = sources
            .first()
            .map(|source| source.url.clone())
            .unwrap_or_else(|| build_ddg_serp_url(query.trim()));

        return Ok(WebEvidenceBundle {
            schema_version: 1,
            retrieved_at_ms: now_ms(),
            tool: "web__search".to_string(),
            backend: "edge:search:fixture".to_string(),
            query: Some(query.trim().to_string()),
            url: Some(source_url),
            sources,
            source_observations: vec![],
            documents: vec![],
            provider_candidates: vec![WebProviderCandidate {
                provider_id: "edge:search:fixture".to_string(),
                affordances: vec![SearchStructuralAffordance::QueryableIndex],
                request_url: Some(build_ddg_serp_url(query.trim())),
                source_count: effective_limit as u32,
                success: true,
                selected: true,
                challenge_reason: None,
            }],
            retrieval_contract: Some(retrieval_contract.clone()),
        });
    }

    let selection_query_contract = query_contract
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| query.trim());
    let locality_hint = resolved_locality_scope(query, query_contract, retrieval_contract);
    let query_for_provider =
        provider_request_query(query, query_contract, retrieval_contract, locality_hint.as_deref());
    let default_serp_url = build_ddg_serp_url(&query_for_provider);
    let requirements =
        search_provider_requirements_from_contract(retrieval_contract, locality_hint.as_deref());
    let expansion_surface_preferred =
        contract_requires_geo_scoped_entity_expansion(retrieval_contract);
    let headline_lookup_mode = retrieval_contract.ordered_collection_preferred
        && retrieval_contract.entity_cardinality_min > 1
        && !retrieval_contract.link_collection_preferred
        && !crate::agentic::web::contract_requires_geo_scoped_entity_expansion(retrieval_contract);
    let excluded_hosts = excluded_hosts_from_query(&query_for_provider);
    let search_started_at_ms = now_ms();
    let mut candidate_observations = Vec::<ObservedSearchProviderCandidate>::new();
    let mut sources: Vec<WebSource> = Vec::new();
    let mut backend = "edge:search:empty".to_string();
    let mut source_url = default_serp_url.clone();
    let provider_result_limit = limit.max(1) as usize;
    let discovery_inventory_limit =
        if expansion_surface_preferred || contract_requires_semantic_source_alignment(retrieval_contract)
        {
            provider_result_limit.max(WEB_SOURCE_ALIGNMENT_MAX_SOURCES)
        } else {
            provider_result_limit
        };
    let mut contributing_backends: Vec<&str> = Vec::new();
    let mut fallback_notes: Vec<String> = Vec::new();

    let mut admitted_descriptors = search_provider_registry()
        .iter()
        .copied()
        .filter(|descriptor| provider_descriptor_is_admissible(&requirements, descriptor))
        .collect::<Vec<_>>();
    admitted_descriptors
        .sort_by_key(|descriptor| provider_probe_priority_key(&requirements, descriptor));

    for descriptor in admitted_descriptors {
        if search_budget_exhausted(search_started_at_ms) {
            fallback_notes.push(format!(
                "search_budget_exhausted_ms={}",
                EDGE_WEB_SEARCH_TOTAL_BUDGET_MS
            ));
            break;
        }
        let observation = probe_search_provider(
            browser,
            descriptor,
            &query_for_provider,
            selection_query_contract,
            retrieval_contract,
            locality_hint.as_deref(),
            headline_lookup_mode,
            discovery_inventory_limit,
            expansion_surface_preferred,
            &excluded_hosts,
        )
        .await;
        if let Some(note) = observation.fallback_note.clone() {
            fallback_notes.push(note);
        }
        candidate_observations.push(observation);
    }

    let mut selected_candidate_indexes = candidate_observations
        .iter()
        .enumerate()
        .filter(|(_, candidate)| {
            provider_candidate_is_usable(&requirements, candidate.selection_input())
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    selected_candidate_indexes.sort_by_key(|index| {
        provider_candidate_selection_key(
            &requirements,
            candidate_observations[*index].selection_input(),
        )
    });
    let preferred_ordered_collection_indexes = if requirements.ordered_collection_preferred {
        selected_candidate_indexes
            .iter()
            .copied()
            .filter(|index| {
                provider_supports_affordance(
                    &candidate_observations[*index].descriptor,
                    SearchStructuralAffordance::OrderedCollection,
                )
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let preferred_only_mode = requirements.ordered_collection_preferred
        && !preferred_ordered_collection_indexes.is_empty();
    let fallback_candidate_indexes = if preferred_only_mode {
        selected_candidate_indexes
            .iter()
            .copied()
            .filter(|index| !preferred_ordered_collection_indexes.contains(index))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let aggregation_order = if preferred_only_mode {
        preferred_ordered_collection_indexes
            .iter()
            .chain(fallback_candidate_indexes.iter())
            .copied()
            .collect::<Vec<_>>()
    } else {
        selected_candidate_indexes.clone()
    };

    for index in aggregation_order {
        let candidate = &mut candidate_observations[index];
        let prior_count = sources.len();
        append_unique_sources(&mut sources, candidate.sources.clone());
        if sources.len() > prior_count {
            candidate.selected = true;
            if let Some(request_url) = candidate.request_url.as_ref() {
                if contributing_backends.is_empty() {
                    source_url = request_url.clone();
                }
            }
            contributing_backends.push(provider_backend_id(candidate.descriptor.stage));
        }
        if should_stop_provider_aggregation(
            retrieval_contract,
            selection_query_contract,
            locality_hint.as_deref(),
            discovery_inventory_limit,
            provider_result_limit,
            &sources,
            Some(&candidate.descriptor),
            preferred_only_mode,
        ) {
            break;
        }
    }

    if !sources.is_empty() {
        if headline_lookup_mode {
            sources = reorder_headline_sources_for_truncation(sources);
        }
        sources.truncate(discovery_inventory_limit);
        for (idx, source) in sources.iter_mut().enumerate() {
            source.rank = Some((idx + 1) as u32);
        }
        if let Some(first_backend) = contributing_backends.first() {
            backend = if contributing_backends
                .iter()
                .all(|candidate| candidate == first_backend)
            {
                (*first_backend).to_string()
            } else {
                let unique_backends = contributing_backends.into_iter().fold(
                    Vec::<&str>::new(),
                    |mut acc, backend_name| {
                        if !acc.contains(&backend_name) {
                            acc.push(backend_name);
                        }
                        acc
                    },
                );
                format!("edge:search:aggregate:{}", unique_backends.join("+"))
            };
        }
    }

    if sources.is_empty() {
        if let Some(challenged_candidate) = candidate_observations
            .iter()
            .find(|candidate| candidate.challenge_reason.is_some())
        {
            if let Some(reason) = challenged_candidate.challenge_reason.as_ref() {
                fallback_notes.push(format!("challenge_required={}", reason));
            }
            if let Some(url) = challenged_candidate.request_url.as_ref() {
                fallback_notes.push(format!("challenge_url={}", url));
                source_url = url.clone();
            }
        }
        if !fallback_notes.is_empty() {
            backend = format!("{}:{}", backend, fallback_notes.join("|"));
        }
    }

    let final_source_keys = sources
        .iter()
        .map(|source| normalize_url_for_id(&source.url))
        .collect::<HashSet<_>>();
    let mut source_observations = Vec::<WebSourceObservation>::new();
    for candidate in &candidate_observations {
        for observation in &candidate.source_observations {
            if final_source_keys.contains(&normalize_url_for_id(&observation.url)) {
                append_unique_source_observations(
                    &mut source_observations,
                    vec![observation.clone()],
                );
            }
        }
    }

    Ok(WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: now_ms(),
        tool: "web__search".to_string(),
        backend,
        query: Some(query_for_provider.clone()),
        url: Some(source_url),
        sources,
        source_observations,
        documents: vec![],
        provider_candidates: candidate_observations
            .iter()
            .map(ObservedSearchProviderCandidate::bundle_candidate)
            .collect(),
        retrieval_contract: Some(retrieval_contract.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_source(url: &str, domain: &str) -> WebSource {
        WebSource {
            source_id: source_id_for_url(url),
            rank: Some(1),
            url: url.to_string(),
            title: None,
            snippet: None,
            domain: Some(domain.to_string()),
        }
    }

    #[test]
    fn excluded_hosts_from_query_extracts_site_tokens() {
        let hosts = excluded_hosts_from_query(
            "latest top news headlines -site:www.fifa.com -site:media.fifa.com",
        );
        assert!(hosts.contains("fifa.com"));
        assert!(hosts.contains("media.fifa.com"));
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn source_matches_excluded_host_filters_matching_domains() {
        let mut excluded = HashSet::new();
        excluded.insert("fifa.com".to_string());

        assert!(source_matches_excluded_host(
            &test_source("https://www.fifa.com/en/news/articles/x", "www.fifa.com"),
            &excluded
        ));
        assert!(source_matches_excluded_host(
            &test_source("https://media.fifa.com/en/news/x", "media.fifa.com"),
            &excluded
        ));
        assert!(!source_matches_excluded_host(
            &test_source("https://www.reuters.com/world/example", "www.reuters.com"),
            &excluded
        ));
    }

    #[test]
    fn headline_reorder_prioritizes_domain_diversity_before_duplicate_domains() {
        let sources = vec![
            test_source("https://www.nbcnews.com/", "www.nbcnews.com"),
            test_source(
                "https://www.reuters.com/world/europe/example-story-2026-03-01/",
                "www.reuters.com",
            ),
            test_source(
                "https://www.apnews.com/article/sample-story-2026-03-01",
                "www.apnews.com",
            ),
        ];
        let reordered = reorder_headline_sources_for_truncation(sources);
        let first_two_domains = reordered
            .iter()
            .take(2)
            .filter_map(canonical_source_domain)
            .collect::<Vec<_>>();
        assert_eq!(first_two_domains.len(), 2);
        assert_ne!(first_two_domains[0], first_two_domains[1]);
    }

    #[test]
    fn provider_request_query_uses_query_contract_bootstrap_for_snapshot_queries() {
        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(
            "current Bitcoin price",
            Some("What's the current price of Bitcoin?"),
        )
        .expect("contract should derive");
        let query = provider_request_query(
            "current Bitcoin price",
            Some("What's the current price of Bitcoin?"),
            &retrieval_contract,
            None,
        );
        let normalized = query.to_ascii_lowercase();
        assert!(
            normalized.contains("bitcoin"),
            "provider query should preserve the subject anchor: {query}"
        );
        assert!(
            normalized.contains("price"),
            "provider query should preserve the metric anchor: {query}"
        );
    }

    #[test]
    fn provider_request_query_preserves_raw_query_when_no_contract_is_available() {
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract("bitcoin price -site:thestreet.com", None)
                .expect("contract should derive");
        let query = provider_request_query(
            "bitcoin price -site:thestreet.com",
            None,
            &retrieval_contract,
            None,
        );
        assert_eq!(query, "bitcoin price -site:thestreet.com");
    }

    #[test]
    fn provider_request_query_prefers_entity_discovery_basis_for_geo_scoped_comparisons() {
        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(
            "best-reviewed Italian restaurants near me",
            Some("Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."),
        )
        .expect("contract should derive");
        let query = provider_request_query(
            "best-reviewed Italian restaurants near me",
            Some("Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."),
            &retrieval_contract,
            Some("Anderson, SC"),
        );
        let normalized = query.to_ascii_lowercase();
        assert!(
            normalized.contains("italian restaurants in anderson")
                || normalized.contains("restaurants in anderson"),
            "expected entity-discovery query basis, got: {query}"
        );
        assert!(
            !normalized.contains("compare"),
            "entity discovery query should not include synthesis directives: {query}"
        );
    }

    #[test]
    fn finalize_provider_sources_respects_explicit_host_exclusions_only() {
        let mut excluded_hosts = HashSet::new();
        excluded_hosts.insert("bitco.in".to_string());
        let filtered = finalize_provider_sources(
            vec![WebSource {
                source_id: source_id_for_url(
                    "https://bitco.in/forum/threads/free-crypto-from-swapzone.90645/",
                ),
                rank: Some(1),
                url: "https://bitco.in/forum/threads/free-crypto-from-swapzone.90645/".to_string(),
                title: Some("Free Crypto from Swapzone | Bitcoin Forum".to_string()),
                snippet: Some(
                    "I want to share a method that made me over $3,000 in 3 days.".to_string(),
                ),
                domain: Some("bitco.in".to_string()),
            }],
            &excluded_hosts,
        );
        assert!(
            filtered.is_empty(),
            "explicit host exclusion should reject matching sources: {:?}",
            filtered
                .iter()
                .map(|source| (&source.url, source.title.as_deref().unwrap_or_default()))
                .collect::<Vec<_>>()
        );
    }
}
