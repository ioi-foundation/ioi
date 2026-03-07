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
fn web_pipeline_constraint_grounded_search_query_preserves_non_locality_queries() {
    let query = constraint_grounded_search_query("summarize this local file", 2);
    assert_eq!(query, "summarize this local file");
}
