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
fn included_hosts_from_query_extracts_positive_site_tokens() {
    let hosts = included_hosts_from_query(
        "nist post quantum cryptography standards site:nist.gov site:www.nist.gov -site:ibm.com",
    );
    assert!(hosts.contains("nist.gov"));
    assert_eq!(hosts.len(), 1);
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
fn source_matches_included_host_accepts_matching_root_and_subdomains() {
    let mut included = HashSet::new();
    included.insert("nist.gov".to_string());

    assert!(source_matches_included_host(
        &test_source(
            "https://www.nist.gov/news-events/news/2024/08/example",
            "www.nist.gov",
        ),
        &included
    ));
    assert!(source_matches_included_host(
        &test_source(
            "https://csrc.nist.gov/projects/post-quantum-cryptography",
            "csrc.nist.gov",
        ),
        &included
    ));
    assert!(!source_matches_included_host(
        &test_source("https://www.ibm.com/think/topics/nist", "www.ibm.com"),
        &included
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
fn provider_request_query_uses_query_contract_even_when_search_query_is_already_grounded() {
    let query_contract =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(
        "best-reviewed Italian restaurants near me",
        Some(query_contract),
    )
    .expect("contract should derive");
    let query = provider_request_query(
        "italian restaurants menus in Anderson, SC \"italian restaurants menus\" \"Anderson, SC\"",
        Some(query_contract),
        &retrieval_contract,
        Some("Anderson, SC"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("italian restaurants in anderson")
            || normalized.contains("restaurants in anderson"),
        "expected query_contract to remain the discovery basis, got: {query}"
    );
    assert!(
        !normalized.contains("\"italian restaurants menus\""),
        "already-grounded menu phrases must not become the provider discovery basis: {query}"
    );
}

#[test]
fn provider_request_query_preserves_explicit_grounded_recovery_probe_query() {
    let query_contract =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(
        "latest nist post quantum cryptography standards",
        Some(query_contract),
    )
    .expect("contract should derive");
    let query = provider_request_query(
        "nist post quantum cryptography standards web UTC timestamp \"nist post quantum cryptography\" \"observed now\" site:nist.gov -site:ibm.com",
        Some(query_contract),
        &retrieval_contract,
        None,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("\"observed now\""),
        "explicit recovery probe phrase should survive provider query reconstruction: {query}"
    );
    assert!(
        normalized.contains("site:nist.gov"),
        "authority site constraint should survive provider query reconstruction: {query}"
    );
    assert!(
        normalized.contains("-site:ibm.com"),
        "recovery host exclusion should survive provider query reconstruction: {query}"
    );
}

#[test]
fn finalize_provider_sources_respects_explicit_host_exclusions_only() {
    let included_hosts = HashSet::new();
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
        &included_hosts,
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

#[test]
fn finalize_provider_sources_respects_explicit_positive_site_constraints() {
    let mut included_hosts = HashSet::new();
    included_hosts.insert("nist.gov".to_string());
    let excluded_hosts = HashSet::new();
    let filtered = finalize_provider_sources(
        vec![
            WebSource {
                source_id: source_id_for_url(
                    "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2",
                ),
                rank: Some(1),
                url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                    .to_string(),
                title: Some(
                    "El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string(),
                ),
                snippet: Some(
                    "IBM overview of the NIST cybersecurity framework.".to_string(),
                ),
                domain: Some("www.ibm.com".to_string()),
            },
            WebSource {
                source_id: source_id_for_url(
                    "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
                ),
                rank: Some(2),
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                snippet: Some(
                    "NIST finalized the first post-quantum encryption standards."
                        .to_string(),
                ),
                domain: Some("www.nist.gov".to_string()),
            },
        ],
        &included_hosts,
        &excluded_hosts,
    );
    assert_eq!(filtered.len(), 1, "filtered={filtered:?}");
    assert!(
        filtered[0].url.contains("nist.gov"),
        "filtered={filtered:?}"
    );
}
