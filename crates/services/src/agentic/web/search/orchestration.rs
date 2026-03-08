use super::super::parsers::{
    fetch_bing_news_rss_sources, fetch_bing_search_rss_sources, fetch_google_news_rss_sources,
    fetch_google_news_top_stories_rss_sources, parse_bing_sources_from_html,
    parse_brave_sources_from_html, parse_ddg_sources_from_html,
    parse_generic_page_source_from_html, parse_google_sources_from_html,
};
use super::super::readability::{extract_non_html_read_blocks, extract_read_blocks};
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
    build_weather_gov_locality_lookup_url,
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
use crate::agentic::desktop::service::step::queue::web_pipeline::{
    constraint_grounded_search_query_with_contract_and_hints_and_locality_hint,
    effective_locality_scope_hint, explicit_query_scope_hint, retrieval_contract_min_sources,
};
use crate::agentic::desktop::service::step::signals::analyze_metric_schema;
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
        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(
            "bitcoin price -site:thestreet.com",
            None,
        )
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
