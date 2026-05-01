use super::super::parsers::{
    fetch_bing_news_rss_sources, fetch_bing_search_rss_sources, fetch_google_news_rss_sources,
    fetch_google_news_top_stories_rss_sources, parse_bing_sources_from_html,
    parse_brave_sources_from_html, parse_ddg_sources_from_html,
    parse_generic_page_source_from_html, parse_google_sources_from_html,
    parse_same_host_child_collection_sources_from_html,
};
use super::super::readability::{extract_non_html_read_blocks, extract_read_blocks_for_url};
use super::super::transport::{
    detect_human_challenge, fetch_html_http_fallback_browser_ua,
    fetch_structured_detail_http_fallback_browser_ua,
    fetch_structured_detail_http_fallback_browser_ua_with_final_url, navigate_browser_retrieval,
};
use super::super::types::{SearchProviderStage, SearchStructuralAffordance};
use super::super::urls::{
    build_bing_news_rss_url, build_bing_search_rss_url, build_bing_serp_url, build_brave_serp_url,
    build_ddg_serp_url, build_google_news_rss_url, build_google_news_serp_url,
    build_google_news_top_stories_rss_url, build_google_serp_url,
    build_restaurantji_locality_root_url, build_weather_gov_locality_lookup_url,
};
use super::super::util::{
    compact_ws, domain_for_url, normalize_url_for_id, now_ms, source_id_for_url,
};
use super::profile::provider_supports_affordance;
use super::{
    extraction::*,
    profile::{
        provider_backend_id, provider_candidate_is_usable, provider_candidate_selection_key,
        provider_descriptor_is_admissible, provider_probe_priority_key, search_budget_exhausted,
        search_provider_registry, search_provider_requirements_from_contract,
        SearchProviderCandidateSelectionInput, SearchProviderDescriptor,
    },
};
use crate::agentic::runtime::service::decision_loop::signals::analyze_metric_schema;
use crate::agentic::runtime::service::queue::web_pipeline::{
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint,
    effective_locality_scope_hint, explicit_query_scope_hint, retrieval_contract_min_sources,
};
use crate::agentic::web::constants::EDGE_WEB_SEARCH_TOTAL_BUDGET_MS;
use crate::agentic::web::{
    contract_requires_geo_scoped_entity_expansion, contract_requires_semantic_source_alignment,
    query_matching_source_urls, WEB_SOURCE_ALIGNMENT_MAX_SOURCES,
};
use anyhow::Result;
use ioi_drivers::browser::BrowserDriver;
use ioi_types::app::agentic::WebRetrievalContract;
use ioi_types::app::agentic::{
    WebEvidenceBundle, WebProviderCandidate, WebSource, WebSourceExpansionAffordance,
    WebSourceObservation,
};
use std::collections::HashSet;

include!("orchestration/source_selection.rs");

include!("orchestration/provider_probe.rs");

include!("orchestration/edge_search.rs");

#[cfg(test)]
#[path = "orchestration/tests.rs"]
mod tests;
