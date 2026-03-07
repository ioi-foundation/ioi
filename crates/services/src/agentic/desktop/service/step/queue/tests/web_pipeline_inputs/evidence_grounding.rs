use super::*;

include!("evidence_grounding/pre_read_filters.rs");

include!("evidence_grounding/local_business_grounding.rs");

#[test]
fn web_pipeline_discovery_affordances_reject_tripadvisor_listing_as_direct_citation() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let source_hints = vec![PendingSearchReadSummary {
        url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
            .to_string(),
        title: Some("Italian Restaurants in Anderson - Tripadvisor".to_string()),
        excerpt:
            "Tripadvisor traveller reviews for Italian restaurants in Anderson, South Carolina."
                .to_string(),
    }];
    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        3,
        &source_hints,
        Some("Anderson, SC"),
    );
    let target_names =
        local_business_target_names_from_sources(&source_hints, Some("Anderson, SC"), 3);

    assert!(query_requires_local_business_entity_diversity(query));
    assert_eq!(projection.locality_scope.as_deref(), Some("Anderson, SC"));
    assert!(projection.query_facets.locality_sensitive_public_fact);
    assert!(projection.query_facets.grounded_external_required);
    assert!(
        target_names.is_empty(),
        "listing page should not yield a concrete business target: {:?}",
        target_names
    );

    let affordances = retrieval_affordances_with_locality_hint(
        query,
        3,
        &source_hints,
        Some("Anderson, SC"),
        &source_hints[0].url,
        source_hints[0].title.as_deref().unwrap_or_default(),
        &source_hints[0].excerpt,
    );

    assert!(
        affordances.contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead),
        "expected listing page to remain usable as a discovery seed: {:?}",
        affordances
    );
    assert!(
        !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead),
        "Tripadvisor locality-wide listing must not be treated as a direct citation: {:?}",
        affordances
    );
}

include!("evidence_grounding/headline_grounding.rs");

#[test]
fn web_pipeline_constraint_grounded_search_limit_tracks_time_sensitive_constraints() {
    assert_eq!(
        constraint_grounded_search_limit("what's the weather right now in anderson sc", 2),
        6
    );
    assert_eq!(
        constraint_grounded_search_limit("summarize this local file", 2),
        10
    );
}

#[test]
fn web_pipeline_uses_source_hints_when_read_output_is_low_signal() {
    let mut pending = PendingSearchCompletion {
        query: "latest breaking news".to_string(),
        query_contract: "latest breaking news".to_string(),
        retrieval_contract: None,
        url: "https://example.com/news".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://example.com/news/storm-delays".to_string()],
        candidate_source_hints: vec![crate::agentic::desktop::types::PendingSearchReadSummary {
            url: "https://example.com/news/storm-delays".to_string(),
            title: Some("Major storm causes widespread flight delays".to_string()),
            excerpt: "Airports across the U.S. reported cancellations and delays overnight."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://example.com/news/storm-delays",
        Some("Google News"),
    );
    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Major storm causes widespread flight delays"));
    assert!(reply.contains("Airports across the U.S."));
}

#[test]
fn web_pipeline_rejects_incompatible_read_evidence_for_grounded_queries() {
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://www.bestbuy.com/trade-in".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.bestbuy.com/trade-in".to_string(),
            title: Some("Trade-In - Best Buy".to_string()),
            excerpt: "Save $50 or more on your next Windows 11 PC with in-store trade-in."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://www.bestbuy.com/trade-in",
        Some("Save $50 on your next PC purchase."),
    );
    assert!(
        pending.successful_reads.is_empty(),
        "incompatible source should not be retained as successful evidence"
    );
}

#[test]
fn web_pipeline_accepts_hint_compatible_read_when_page_extract_is_low_signal() {
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec!["https://weather.com/weather/today/l/Anderson+SC".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt:
                "Current conditions in Anderson, SC: temperature 62 F, humidity 42%, wind 4 mph."
                    .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://weather.com/weather/today/l/Anderson+SC",
        Some("Weather navigation and legal terms."),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("temperature"),
        "expected compatible hint excerpt to be retained"
    );
}

#[test]
fn web_pipeline_hint_lookup_matches_structurally_equivalent_urls() {
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Current Weather - Anderson, SC".to_string()),
            excerpt: "Current weather in Anderson, SC: temperature 61 F, humidity 48%, wind 3 mph."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    append_pending_web_success_fallback(
        &mut pending,
        "https://forecast.weather.gov/zipcity.php?inputstring=Anderson%2CSC",
        Some("Cookie banner and navigation links."),
    );

    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("current weather in anderson"),
        "expected structurally equivalent URL to reuse compatible hint evidence"
    );
}

include!("evidence_grounding/bundle_recovery.rs");

#[test]
fn web_pipeline_metadata_noise_excerpt_is_rejected_and_replaced_by_hint_payload() {
    let requested_url = "https://www.foxnews.com/";
    let mut pending = PendingSearchCompletion {
        query: "today's top news headlines".to_string(),
        query_contract: "today's top news headlines".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Fox News - Breaking News Updates".to_string()),
            excerpt: "Breaking news updates across U.S. and world stories today.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };
    let metadata_blob = r#"{"@context":"https://schema.org","@type":"NewsMediaOrganization","datePublished":"1996-10-07","inLanguage":"en","image":{"@type":"ImageObject","width":1200,"height":630,"caption":"Fox News - Breaking News and Latest Headlines"}}"#;
    assert!(looks_like_structured_metadata_noise(metadata_blob));
    assert!(looks_like_structured_metadata_noise(
        "Pepe Giallo: com','cookie':'trip-cookie-payload-67890"
    ));
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:fox-home".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some("Fox News".to_string()),
            snippet: None,
            domain: Some("foxnews.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:fox-home".to_string(),
            url: requested_url.to_string(),
            title: Some("Fox News".to_string()),
            content_text: metadata_blob.to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);
    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        !pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("datepublished"),
        "metadata blob should be filtered from excerpts"
    );
    assert!(
        pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("breaking news"),
        "expected fallback to retain actionable search-hint excerpt"
    );
}

include!("evidence_grounding/snapshot_grounding.rs");

#[test]
fn web_pipeline_merge_pending_search_completion_preserves_existing_inventory() {
    let existing = PendingSearchCompletion {
        query: "what's the weather right now".to_string(),
        query_contract: "what's the weather right now".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=weather".to_string(),
        started_step: 3,
        started_at_ms: 1_000,
        deadline_ms: 51_000,
        candidate_urls: vec![
            "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Current Conditions - National Weather Service".to_string()),
            excerpt: "Current conditions at local airport with temperature and humidity."
                .to_string(),
        }],
        attempted_urls: vec!["https://weather.com/weather/today/l/Anderson+SC".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };
    let incoming = PendingSearchCompletion {
        query: "what's the weather right now".to_string(),
        query_contract: "what's the weather right now".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/html/?q=weather".to_string(),
        started_step: 5,
        started_at_ms: 2_000,
        deadline_ms: 52_000,
        candidate_urls: vec![
            "https://duckduckgo.com/feedback.html".to_string(),
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://duckduckgo.com/feedback.html".to_string(),
            title: Some("Feedback".to_string()),
            excerpt: "Submit feedback".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };

    let merged = merge_pending_search_completion(existing, incoming);
    assert_eq!(merged.started_at_ms, 1_000);
    assert_eq!(merged.deadline_ms, 51_000);
    assert_eq!(merged.min_sources, 2);
    assert_eq!(
        merged.attempted_urls,
        vec!["https://weather.com/weather/today/l/Anderson+SC".to_string()]
    );
    assert_eq!(
        merged.candidate_urls,
        vec![
            "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            "https://duckduckgo.com/feedback.html".to_string(),
        ]
    );
    assert!(merged
        .candidate_source_hints
        .iter()
        .any(|hint| hint.url.contains("forecast.weather.gov")));
}
