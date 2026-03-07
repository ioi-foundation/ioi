use super::*;

#[test]
fn web_pipeline_constraint_grounded_search_query_appends_typed_facets() {
    let query =
        constraint_grounded_search_query("what is the current price of bitcoin right now", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("current bitcoin price"),
        "single-snapshot metric bootstrap should start from the semantic metric target: {query}"
    );
    assert!(
        !normalized.contains("latest measured data")
            && !normalized.contains("as-of observation")
            && !normalized.contains("independent sources"),
        "probe-only escalation terms should stay out of the bootstrap query: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_with_hints_adds_anchor_phrase() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Current weather Anderson South Carolina".to_string()),
            excerpt:
                "Current conditions in Anderson South Carolina: temperature 62 F, humidity 44%."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Anderson South Carolina current conditions".to_string()),
            excerpt: "Observed weather for Anderson South Carolina: temperature 60 F, wind 3 mph."
                .to_string(),
        },
    ];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("\""));
}

#[test]
fn web_pipeline_constraint_grounded_search_query_anchor_phrase_ignores_output_contract_terms() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Current weather Anderson South Carolina".to_string()),
            excerpt:
                "Current conditions in Anderson South Carolina: temperature 62 F, humidity 44%."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC".to_string(),
            title: Some("Anderson South Carolina current conditions".to_string()),
            excerpt: "Observed weather for Anderson South Carolina: temperature 60 F, wind 3 mph."
                .to_string(),
        },
    ];

    let query = constraint_grounded_search_query_with_hints(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
        &hints,
    );
    let normalized = query.to_ascii_lowercase();
    let utc_phrase_count = normalized.match_indices("utc timestamp").count();
    assert_eq!(
        utc_phrase_count, 1,
        "expected deduped output-contract term in query: {query}"
    );
    assert!(
        !normalized.contains("\"anderson sources"),
        "anchor phrase should be semantic-only: {query}"
    );
    assert!(
        !normalized.contains("\"sources utc"),
        "anchor phrase should be semantic-only: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_projects_semantic_target_when_provenance_directives_present(
) {
    let query = constraint_grounded_search_query(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "expected semantic retrieval projection: {query}"
    );
    assert!(normalized.contains("anderson"), "query={query}");
    assert!(
        !normalized.starts_with("current weather in anderson, sc right now with sources"),
        "retrieval query should not be dominated by output-contract directives: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_projects_semantic_target_for_locality_query() {
    let query =
        constraint_grounded_search_query("What's the weather right now in Anderson, SC?", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "expected locality-scoped semantic projection: {query}"
    );
    assert!(normalized.contains("anderson"), "query={query}");
    assert!(
        !normalized.starts_with("what's the weather right now"),
        "retrieval query should avoid conversational framing: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_bootstrap_keeps_scoped_time_sensitive_query_concise(
) {
    let query = constraint_grounded_search_query(
        "Current weather in Anderson, SC right now with sources and UTC timestamp.",
        2,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "query={}",
        query
    );
    assert!(normalized.contains("anderson"), "query={}", query);
    assert!(
        !normalized.contains("latest measured data"),
        "query={}",
        query
    );
    assert!(
        !normalized.contains("independent sources"),
        "query={}",
        query
    );
    assert!(!normalized.contains("utc timestamp"), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_infers_locality_scope_from_candidate_hints() {
    let hints = vec![PendingSearchReadSummary {
        url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
        title: Some("Anderson, SC current weather".to_string()),
        excerpt:
            "Current conditions in Anderson, South Carolina: temperature 62 F, humidity 42%, wind 4 mph."
                .to_string(),
    }];
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now",
        2,
        &hints,
        None,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("anderson"),
        "expected inferred locality token in grounded query: {}",
        query
    );
    assert!(
        normalized.contains("sc"),
        "expected inferred locality token in grounded query: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_does_not_infer_scope_from_rss_proxy_tokens() {
    let hints = vec![PendingSearchReadSummary {
        url: "https://news.google.com/rss/articles/CBMimAFBVV95cUxNcVZDZVYtQXVXRFlLQmdCVnVuVlZjMlNZcTNGWm9WN0ZPb0pvMUpBMllJVFo0V3IxZ21RNUtQZTVkc3Joc0c2U2V6ZlA0OHEwdTlHNm8zanp5QmlUUERSVzBQTXJUMXlEVXctZkhUT085SVBvWmVjRWZPNFE4NFZ3LUpOemMyekVMVlRXejl6cHdjYUM2R3cxcw?oc=5".to_string(),
        title: None,
        excerpt: String::new(),
    }];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "scope should stay unresolved when hints are rss proxy links: {}",
        query
    );
    assert!(
        !normalized.contains("rss") && !normalized.contains("articles"),
        "rss proxy path tokens should not leak into inferred scope: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_avoids_scope_inference_from_non_resolvable_hints()
{
    let hints = vec![PendingSearchReadSummary {
        url: "https://forums.x-plane.org/forums/topic/337131-weather-radar-not-working-for-me/"
            .to_string(),
        title: Some("Weather radar not working for me - X-Plane.Org Forum".to_string()),
        excerpt: "Despite updates to aircraft and sim builds, weather radar does not appear on ND."
            .to_string(),
    }];

    let query =
        constraint_grounded_search_query_with_hints("what's the weather right now", 2, &hints);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "scope should stay unresolved for non-resolvable hints: {}",
        query
    );
    assert!(
        !normalized.contains("forum") && !normalized.contains("plane"),
        "non-resolvable hint tokens should not leak into query scope: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_bootstrap_applies_trusted_locality_hint_without_hints(
) {
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now",
        2,
        &[],
        Some("Anderson, SC"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "query={}",
        query
    );
    assert!(normalized.contains("anderson"), "query={}", query);
    assert!(
        normalized.contains("sc"),
        "query should preserve trusted locality tokens: {}",
        query
    );
    assert!(
        !normalized.contains("\"near me\""),
        "query should avoid locality placeholder terms when scope is resolved: {}",
        query
    );
    assert!(
        !normalized.contains("latest measured data"),
        "query={}",
        query
    );
    assert!(!normalized.contains("as-of observation"), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_scopes_local_business_lookup_with_trusted_locality(
) {
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &[],
        Some("New York, NY"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("italian"),
        "query should preserve cuisine anchor: {}",
        query
    );
    assert!(
        normalized.contains("restaurants"),
        "query should preserve entity anchor: {}",
        query
    );
    assert!(
        normalized.contains("new york"),
        "query should include trusted locality scope: {}",
        query
    );
    assert!(
        !normalized.contains("near me"),
        "query should resolve the locality placeholder: {}",
        query
    );
}

#[test]
fn web_pipeline_runtime_locality_scope_keeps_near_me_unresolved_until_runtime_scope_is_bound() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    assert_eq!(explicit_query_scope_hint(query), None);
    assert!(query_requires_runtime_locality_scope(query));
}

#[test]
fn web_pipeline_resolved_query_contract_replaces_locality_placeholder_with_trusted_scope() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let resolved = resolved_query_contract_with_locality_hint(query, Some("New York, NY"));
    let normalized = resolved.to_ascii_lowercase();
    assert!(
        normalized.contains("in new york, ny"),
        "resolved contract should bind the trusted locality: {}",
        resolved
    );
    assert!(
        !normalized.contains("near me"),
        "resolved contract should replace the unresolved placeholder: {}",
        resolved
    );
    assert!(
        normalized.contains("compare their menus"),
        "resolved contract should preserve the comparison clause: {}",
        resolved
    );
}

#[test]
fn web_pipeline_explicit_query_scope_hint_truncates_follow_on_comparison_clause() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York and compare their menus.";
    assert_eq!(
        explicit_query_scope_hint(query).as_deref(),
        Some("New York")
    );
}

#[test]
fn web_pipeline_probe_hint_anchor_phrase_ignores_single_source_noise_for_restaurant_lookup() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://nypost.com/2026/01/21/lifestyle/new-york-city-restaurant-tops-yelps-100-best-restaurants-in-america/".to_string(),
            title: Some(
                "New York City restaurant tops Yelp's 100 best restaurants in America"
                    .to_string(),
            ),
            excerpt: "Ranking page for best restaurants in America.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://support.microsoft.com/topic/how-bing-delivers-search-results-d18fc815-ac37-4723-bc67-9229ce3eb6a3?".to_string(),
            title: Some("How Bing delivers search results - Microsoft Support".to_string()),
            excerpt: "https://support.microsoft.com/topic/how-bing-delivers-search-results-d18fc815-ac37-4723-bc67-9229ce3eb6a3? source_url=https://support.microsoft.com/topic/how-bing-delivers-search-results-d18fc815-ac37-4723-bc67-9229ce3eb6a3?".to_string(),
        },
    ];

    let projection = build_query_constraint_projection_with_locality_hint(query, 3, &hints, None);
    assert_eq!(
        projection_probe_hint_anchor_phrase(&projection, &hints),
        None,
        "single-source ranking/support noise should not become a quoted probe anchor"
    );
}

#[test]
fn web_pipeline_query_shape_detects_explicit_count_for_restaurant_comparison() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    assert_eq!(required_story_count(query), 3);
    assert!(query_prefers_multi_item_cardinality(query));
    assert!(query_requests_comparison(query));
    assert!(query_requires_structured_synthesis(query));
}

#[test]
fn web_pipeline_constraint_grounded_search_query_uses_resolved_contract_for_local_business_lookup()
{
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &[],
        Some("New York, NY"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("italian restaurants"),
        "query should preserve the semantic entity target: {}",
        query
    );
    assert!(
        normalized.contains("menus"),
        "query should preserve the comparison target: {}",
        query
    );
    assert!(
        normalized.contains("new york"),
        "query should preserve the resolved locality scope: {}",
        query
    );
    assert!(
        !normalized.contains("near me"),
        "query should resolve locality placeholders: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_does_not_infer_metric_probe_terms_for_restaurant_comparison(
) {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurant_Review-g30090-d15074041-Reviews-DolceVita_Italian_Bistro_Pizzeria-Anderson_South_Carolina.html".to_string(),
            title: Some(
                "DOLCEVITA ITALIAN BISTRO PIZZERIA, Anderson - Restaurant Reviews, Photos & Phone Number - Tripadvisor".to_string(),
            ),
            excerpt: "Italian restaurant with menu details, reviews, and reservation information."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.yelp.com/biz/dolce-vita-italian-bistro-and-pizzeria-anderson"
                .to_string(),
            title: Some(
                "DOLCE VITA ITALIAN BISTRO AND PIZZERIA - Updated February 2026 - Yelp"
                    .to_string(),
            ),
            excerpt: "Restaurant reviews, menu, hours, and phone number for Anderson, SC."
                .to_string(),
        },
    ];

    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        Some("Anderson, SC"),
    );
    let normalized = grounded.to_ascii_lowercase();
    assert!(
        normalized.contains("italian restaurants"),
        "query should preserve the local-business target: {}",
        grounded
    );
    assert!(
        normalized.contains("anderson"),
        "query should preserve the trusted locality scope: {}",
        grounded
    );
    assert!(
        !normalized.contains("duration"),
        "local-business comparison should not infer metric probe facets: {}",
        grounded
    );
    assert!(
        !normalized.contains("independent sources"),
        "local-business comparison should not inject metric provenance search terms: {}",
        grounded
    );
    assert!(
        !normalized.contains("observed"),
        "local-business comparison should not inject observation probe markers: {}",
        grounded
    );
}

#[test]
fn web_pipeline_probe_hint_anchor_phrase_skips_scope_grounded_local_business_noise() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://observer.com/list/best-new-restaurant-openings-new-york-city-november-2025/".to_string(),
            title: Some(
                "Best New Restaurant Openings in New York City: November 2025 | Observer"
                    .to_string(),
            ),
            excerpt: "Roundup of recently opened restaurants across New York City.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.msn.com/en-us/food-and-drink/world-cuisines/italian-restaurants-in-new-york-so-good-locals-try-to-keep-them-secret/ar-AA1Q3Ayl".to_string(),
            title: Some("MSN".to_string()),
            excerpt: "Italian restaurants in New York so good locals try to keep them secret."
                .to_string(),
        },
    ];

    let projection = build_query_constraint_projection_with_locality_hint(
        query,
        3,
        &hints,
        Some("New York, NY"),
    );
    assert_eq!(
        projection_probe_hint_anchor_phrase(&projection, &hints),
        None,
        "scope-grounded local business lookups should not inherit hint-derived quoted anchors"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_avoids_status_fallback_for_local_business_lookup() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        3,
        &[],
        Some("New York, NY"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        3,
        &[],
        &grounded,
        Some("New York, NY"),
    );
    assert!(
        probe.is_none(),
        "without discovery-backed hint evidence the probe query should abstain instead of inventing new lexical fallback terms: {:?}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_excludes_noisy_hosts_for_local_business_lookup() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.reddit.com/r/Italian/".to_string(),
            title: Some("r/Italian".to_string()),
            excerpt: "Italian language and culture discussion community.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://news.google.com/rss/articles/CBMiakFVX3lxTE1paDlDQVMzckpVZjltZkhUM3RSdFh4MGtVOHFGNll6NlRKNUpqOV9UVDl4ZlBXZldpcUtMNm9JLWtZZ0dSMHlORTBRVlZTNC1mZ1dCemkzaWRCcmFMN2E5VVlZallSYjI5MVE?oc=5".to_string(),
            title: Some("Google News".to_string()),
            excerpt: "News feed entry for restaurant coverage.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        Some("New York, NY"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        &grounded,
        Some("New York, NY"),
    )
    .expect("probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.reddit.com") || normalized.contains("-site:reddit.com"),
        "probe query should exclude noisy Reddit hosts: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_escalates_when_prior_query_differs_for_local_business_lookup(
) {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.reddit.com/r/Italian/".to_string(),
        title: Some("r/Italian".to_string()),
        excerpt: "Italian language and culture discussion community.".to_string(),
    }];
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        "italian restaurants near me",
        Some("New York, NY"),
    )
    .expect("probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.reddit.com") || normalized.contains("-site:reddit.com"),
        "probe query should preserve discovery-backed host exclusions even when prior query differs: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_keeps_metric_subject_ahead_of_noisy_price_hosts() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://help.price.com/knowledge-base/about-price-com/".to_string(),
            title: Some("About Price.com - Help Center".to_string()),
            excerpt: "Learn about Price.com and how the help center works.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://price.com/about".to_string(),
            title: Some("About Price.com".to_string()),
            excerpt: "Company background and press information for Price.com.".to_string(),
        },
    ];

    let query = constraint_grounded_search_query_with_hints(
        "What's the current price of Bitcoin?",
        2,
        &hints,
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("current bitcoin price"),
        "metric subject should stay ahead of noisy host lexemes: {query}"
    );
    assert!(
        !normalized.contains("about help center"),
        "grounded search query should not inherit provider-noise phrases: {query}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_excludes_noisy_price_hosts() {
    let query = "What's the current price of Bitcoin?";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://help.price.com/knowledge-base/about-price-com/".to_string(),
            title: Some("About Price.com - Help Center".to_string()),
            excerpt: "Learn about Price.com and how the help center works.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://price.com/about".to_string(),
            title: Some("About Price.com".to_string()),
            excerpt: "Company background and press information for Price.com.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 2, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 2, &hints, &grounded, None,
    )
    .expect("probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.starts_with("current bitcoin price"),
        "probe should preserve the typed metric subject: {probe}"
    );
    assert!(
        normalized.contains("-site:price.com") || normalized.contains("-site:help.price.com"),
        "probe query should exclude noisy price.com hosts: {probe}"
    );
    assert!(
        !normalized.contains("about help center"),
        "probe query should not inherit provider-specific title noise: {probe}"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_escalates_when_prior_query_differs_for_price_lookup(
) {
    let query = "What's the current price of Bitcoin?";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.reddit.com/r/CryptoCurrency/comments/14zq3b4/why_is_the_bitcoin_price_falling_what_is_the/"
            .to_string(),
        title: Some("Why is the Bitcoin price falling?".to_string()),
        excerpt: "Current BTC price is $68,123, but this thread is community speculation about where it goes next."
            .to_string(),
    }];
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        "bitcoin price",
        None,
    )
    .expect("probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("-site:www.reddit.com") || normalized.contains("-site:reddit.com"),
        "probe query should preserve discovery-backed host exclusions even when prior query differs: {}",
        probe
    );
}

#[test]
fn web_pipeline_local_business_entity_anchor_filter_rejects_generic_italian_noise() {
    let search_query = "\"italian restaurants\" menus reviews ratings \"New York, NY\"";

    assert!(source_matches_local_business_search_entity_anchor(
        search_query,
        None,
        Some("New York, NY"),
        "https://www.theinfatuation.com/new-york/guides/best-italian-restaurants-nyc",
        "The Best Italian Restaurants In NYC",
        "A guide to the best Italian restaurants in New York City.",
    ));
    assert!(!source_matches_local_business_search_entity_anchor(
        search_query,
        None,
        Some("New York, NY"),
        "https://www.reddit.com/r/Italian/",
        "r/Italian",
        "Italian language and culture discussion community.",
    ));
}

#[test]
fn web_pipeline_local_business_entity_anchor_filter_rejects_wrong_frankies_business() {
    let search_query = "\"Frankies 457 Spuntino\" italian restaurant menu \"New York, NY\"";

    assert!(source_matches_local_business_search_entity_anchor(
        search_query,
        None,
        Some("New York, NY"),
        "https://www.frankiesspuntino.com/",
        "Frankies Spuntino",
        "Italian restaurant in New York, NY with pasta, antipasti and wine.",
    ));
    assert!(!source_matches_local_business_search_entity_anchor(
        search_query,
        None,
        Some("New York, NY"),
        "https://frankiesnywings.com/",
        "Frankie's New York Buffalo Wings - The Biggest Baddest Wings in Metro Manila",
        "How it works: Earning of points: 2% cash back for every transaction.",
    ));
}

#[test]
fn web_pipeline_local_business_entity_anchor_ignores_quoted_locality_scope() {
    let search_query = "\"Roscioli\" italian restaurant menu \"New York, NY\"";

    assert_eq!(
        local_business_search_entity_anchor_tokens(search_query, Some("New York, NY")),
        vec!["roscioli".to_string()]
    );
}

#[test]
fn web_pipeline_local_business_target_name_normalizes_numeric_parenthetical_modifier() {
    let attempted_urls = vec![format!(
        "ioi://local-business-expansion/query/{}",
        local_business_expansion_query(
            "Frankies (457) Spuntino",
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
            Some("New York, NY"),
        )
        .expect("expansion query")
    )];
    let targets =
        local_business_target_names_from_attempted_urls(&attempted_urls, Some("New York, NY"));

    assert_eq!(targets, vec!["Frankies Spuntino".to_string()]);
}

#[test]
fn web_pipeline_local_business_expansion_query_strips_multi_entity_directives() {
    let query = local_business_expansion_query(
        "Brothers Italian Cuisine",
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
        Some("Anderson, SC"),
    )
    .expect("expansion query");
    let lower = query.to_ascii_lowercase();

    assert!(
        lower.contains("\"brothers italian cuisine\""),
        "target name should remain bound in the expansion query: {}",
        query
    );
    assert!(
        lower.contains("\"anderson, sc\""),
        "locality scope should remain bound in the expansion query: {}",
        query
    );
    assert!(
        lower.contains("italian"),
        "semantic cuisine anchor should remain in the expansion query: {}",
        query
    );
    assert!(
        !lower.contains(" compare ")
            && !lower.contains(" best ")
            && !lower.contains(" reviewed ")
            && !lower.contains(" review ")
            && !lower.contains(" ratings "),
        "multi-entity/ranking directives must not leak into single-entity expansion queries: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_prefers_explicit_locality_over_trusted_hint() {
    let query = constraint_grounded_search_query_with_hints_and_locality_hint(
        "what's the weather right now in Boise, ID",
        2,
        &[],
        Some("Anderson, SC"),
    );
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.contains("boise"),
        "query should preserve explicit query locality: {}",
        query
    );
    assert!(
        normalized.contains("id"),
        "query should preserve explicit query locality tokens: {}",
        query
    );
    assert!(
        !normalized.contains("anderson"),
        "trusted locality hint must not override explicit query locality: {}",
        query
    );
}

#[test]
fn web_pipeline_select_query_contract_prefers_scope_grounded_retrieval_query() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now",
        "what's the weather right now in Anderson, SC",
    );
    let normalized = selected.to_ascii_lowercase();
    assert!(normalized.starts_with("what's the weather right now in"));
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("sc"));
}

#[test]
fn web_pipeline_select_query_contract_preserves_goal_when_it_has_scope_and_retrieval_does_not() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now in Anderson, SC",
        "what's the weather right now",
    );
    assert_eq!(selected, "what's the weather right now in Anderson, SC");
}

#[test]
fn web_pipeline_select_query_contract_drops_probe_term_inflation_from_retrieval_query() {
    let selected = select_web_pipeline_query_contract(
        "what's the weather right now",
        "what's the weather right now in Anderson, SC \"anderson weather\" \"anderson weather\" \"anderson weather\"",
    );
    let normalized = selected.to_ascii_lowercase();
    assert!(normalized.starts_with("what's the weather right now in"));
    assert!(normalized.contains("anderson"));
    assert!(normalized.contains("sc"));
    assert!(!normalized.contains("\""));
    assert!(
        !normalized.contains("anderson weather"),
        "scope merge should not include probe-term inflation: {}",
        selected
    );
}

#[test]
fn web_pipeline_select_query_contract_prefers_runtime_scope_over_probe_expansion() {
    std::env::set_var("IOI_SESSION_LOCALITY", "Anderson, SC");
    let selected = select_web_pipeline_query_contract(
        "What's the weather like right now?",
        "weather current conditions temperature humidity wind in Anderson, SC \"Anderson, SC\" \"observed now\"",
    );
    std::env::remove_var("IOI_SESSION_LOCALITY");
    assert_eq!(
        selected,
        "What's the weather like right now in Anderson, SC?"
    );
}

#[test]
fn web_pipeline_select_query_contract_rejects_semantic_fragment_as_scope() {
    let selected = select_web_pipeline_query_contract(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        "Find the three best-reviewed Italian restaurants in Anderson, SC italian restaurants menus Anderson, SC and compare their menus.",
    );
    assert_eq!(
        selected,
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_avoids_locality_placeholder_when_scope_missing() {
    let query = constraint_grounded_search_query("what's the weather right now", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(normalized.starts_with("weather current conditions"));
    assert!(!normalized.contains("\"near me\""), "query={}", query);
}

#[test]
fn web_pipeline_constraint_grounded_search_query_avoids_native_anchor_phrase_for_explicit_locality()
{
    let query =
        constraint_grounded_search_query("What's the weather right now in Anderson, SC?", 2);
    let normalized = query.to_ascii_lowercase();
    assert!(
        normalized.starts_with("weather current conditions"),
        "query={}",
        query
    );
    assert!(normalized.contains("anderson"), "query={}", query);
    assert!(
        !normalized.contains("\"anderson weather\""),
        "query should avoid quoted native-anchor inflation for explicit-locality lookups: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_ignores_forecast_only_axis_hints() {
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://weather.example.com/a".to_string(),
            title: Some("Anderson forecast".to_string()),
            excerpt: "Tomorrow forecast: high 65, low 49, chance of rain 60%.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://weather2.example.com/b".to_string(),
            title: Some("Anderson 10-day outlook".to_string()),
            excerpt: "Weekly outlook with precipitation chance and daily high/low values."
                .to_string(),
        },
    ];

    let query = constraint_grounded_search_query_with_hints(
        "What's the weather right now in Anderson, SC?",
        2,
        &hints,
    );
    assert!(
        !query.to_ascii_lowercase().contains("precipitation values"),
        "forecast-only hints should not infer precipitation axis constraints: {}",
        query
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_escalates_when_prior_equals_grounded() {
    let query = "what's the weather right now";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.weather-atlas.com/en/wyoming-usa/cheyenne".to_string(),
        title: Some("Weather today - Cheyenne, WY".to_string()),
        excerpt:
            "Current weather in Cheyenne, Wyoming: temperature 30 F, humidity 68%, wind 11 mph."
                .to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        Some("Anderson, SC"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &hints,
        &grounded,
        Some("Anderson, SC"),
    )
    .expect("probe query should be generated");
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "probe should differ from prior grounded query"
    );
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("cheyenne") || normalized.contains("wyoming"),
        "expected locality-aware escalation terms in probe query: {}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_adds_metric_probe_terms_when_locality_query_stalls()
{
    let query = "what's the weather right now";
    let grounded = constraint_grounded_search_query_with_hints_and_locality_hint(
        query,
        2,
        &[],
        Some("New York"),
    );
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        2,
        &[],
        &grounded,
        Some("New York"),
    )
    .expect("probe query should be generated for stalled locality-sensitive query");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        normalized.contains("temperature")
            && normalized.contains("humidity")
            && normalized.contains("wind"),
        "expected metric-oriented fallback probe terms: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&grounded),
        "fallback probe query should differ from grounded query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_stays_stable_for_headlines_when_grounded_query_matches(
) {
    let query = "Tell me today's top news headlines.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://sentinelcolorado.com/nation-world/world/friday-news-in-a-rush-top-headlines-in-todays-newsminute-video-257/"
                .to_string(),
            title: Some(
                "FRIDAY NEWS IN A RUSH: Top headlines in today's NewsMinute video - Sentinel Colorado"
                    .to_string(),
            ),
            excerpt: "Top world headlines and daily roundup.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026"
                .to_string(),
            title: Some("Top news headlines for Thursday, March 5, 2026".to_string()),
            excerpt: "Local roundup of the day's top headlines.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384"
                .to_string(),
            title: Some(
                "Today in Africa — Mar 6, 2026: WAFCON Postponed, Uganda Evacuates 43 Students From Iran"
                    .to_string(),
            ),
            excerpt:
                "Uganda evacuated 43 students from Iran while WAFCON was postponed, according to today's regional report."
                    .to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 3, &hints, &grounded, None,
    );
    assert!(
        probe.is_none(),
        "headline probe query should not append lexical host exclusions when the grounded query is unchanged; got {:?}",
        probe
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_removes_site_exclusions_when_present_in_prior() {
    let query = "Tell me today's top news headlines.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.foxnews.com/us/example-headline".to_string(),
            title: Some("Top headlines from Fox News".to_string()),
            excerpt: "Breaking U.S. and world coverage from Fox.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://video.foxnews.com/v/123".to_string(),
            title: Some("Live coverage stream".to_string()),
            excerpt: "Video stream from Fox News.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let prior_probe = format!("{grounded} -site:www.foxnews.com -site:video.foxnews.com");
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query,
        3,
        &hints,
        &prior_probe,
        None,
    )
    .expect("headline follow-up probe query should be generated");
    let normalized = probe.to_ascii_lowercase();
    assert!(
        !normalized.contains("-site:"),
        "headline probe query should not retain site exclusions: {}",
        probe
    );
    assert!(
        !probe.eq_ignore_ascii_case(&prior_probe),
        "follow-up probe should differ from previous probe query"
    );
}

#[test]
fn web_pipeline_constraint_grounded_search_query_keeps_generic_headline_contract_clean() {
    let query = "Tell me today's top news headlines.";
    let hints = vec![PendingSearchReadSummary {
        url: "https://www.foxnews.com/us/example-headline?msockid=abc123".to_string(),
        title: Some("Dems score rare Florida win and more top headlines".to_string()),
        excerpt: "Breaking updates from Fox with msockid=abc123 tracking.".to_string(),
    }];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let normalized = grounded.to_ascii_lowercase();
    assert!(
        normalized.contains("top")
            && normalized.contains("news")
            && normalized.contains("headlines")
            && (normalized.contains("today") || normalized.contains("latest")),
        "headline grounded query should preserve headline intent anchors: {}",
        grounded
    );
    assert!(
        !normalized.contains("score values")
            && !normalized.contains("independent sources")
            && !normalized.contains("msockid"),
        "headline grounded query should avoid metric and tracking-noise terms: {}",
        grounded
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_avoids_host_exclusion_terms_for_metric_gaps() {
    let query = "what's the weather right now in anderson, sc";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.weather-forecast.com/locations/Anderson/forecasts/latest".to_string(),
            title: Some("Anderson, South Carolina Weather Forecast".to_string()),
            excerpt: "Providing a local hourly Anderson (South Carolina) weather forecast."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.accuweather.com/en/us/anderson/29624/weather-forecast/330677"
                .to_string(),
            title: Some("Anderson, SC Weather Forecast".to_string()),
            excerpt: "Anderson, SC Weather Forecast, with current conditions and next 3 days."
                .to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 2, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 2, &hints, &grounded, None,
    );
    if let Some(candidate) = probe {
        let normalized = candidate.to_ascii_lowercase();
        assert!(
            !normalized.contains("-site:"),
            "probe query should not contain host-exclusion operators: {}",
            candidate
        );
    }
}

#[test]
fn web_pipeline_constraint_grounded_search_query_adds_status_surface_terms_for_incident_queries() {
    let query = "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with citations.";
    let grounded = constraint_grounded_search_query(query, 3);
    let normalized = grounded.to_ascii_lowercase();
    assert!(
        normalized.contains("official status page"),
        "expected status-surface grounding term: {}",
        grounded
    );
    assert!(
        normalized.contains("service health dashboard"),
        "expected service-health grounding term: {}",
        grounded
    );
}

#[test]
fn web_pipeline_constraint_grounded_probe_query_avoids_host_exclusions_for_incident_queries() {
    let query = "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents from major status pages with citations.";
    let hints = vec![
        PendingSearchReadSummary {
            url: "https://www.reddit.com/r/MicrosoftTeams/comments/1crvhbg/accidentally_found_the_best_way_to_keep_active/".to_string(),
            title: Some("Accidentally found the best way to keep active status".to_string()),
            excerpt: "Discussion thread repeating active-status phrasing.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.reddit.com/r/WindowsHelp/comments/17qndbf/search_active_directory_in_windows_11/".to_string(),
            title: Some("Search Active Directory in Windows 11".to_string()),
            excerpt: "Another thread unrelated to provider status dashboards.".to_string(),
        },
    ];
    let grounded = constraint_grounded_search_query_with_hints(query, 3, &hints);
    let probe = constraint_grounded_probe_query_with_hints_and_locality_hint(
        query, 3, &hints, &grounded, None,
    );
    if let Some(candidate) = probe {
        let normalized = candidate.to_ascii_lowercase();
        assert!(
            !normalized.contains("-site:"),
            "probe query should not contain host-exclusion operators: {}",
            candidate
        );
    }
}

#[test]
fn web_pipeline_constraint_grounded_search_query_preserves_non_locality_queries() {
    let query = constraint_grounded_search_query("summarize this local file", 2);
    assert_eq!(query, "summarize this local file");
}
