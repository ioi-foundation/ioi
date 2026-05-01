#[test]
fn web_pipeline_pre_read_locality_scope_hint_filters_non_local_weather_candidates() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("what's the weather right now".to_string()),
        url: Some("https://duckduckgo.com/?q=weather+right+now".to_string()),
        sources: vec![
            WebSource {
                source_id: "anderson-local".to_string(),
                rank: Some(1),
                url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
                title: Some("Anderson, SC current weather".to_string()),
                snippet: Some(
                    "Current conditions in Anderson, South Carolina: temperature 62 F, humidity 42%, wind 4 mph."
                        .to_string(),
                ),
                domain: Some("weather.com".to_string()),
            },
            WebSource {
                source_id: "cheyenne-non-local".to_string(),
                rank: Some(2),
                url: "https://www.weather-atlas.com/en/wyoming-usa/cheyenne".to_string(),
                title: Some("Weather today - Cheyenne, WY".to_string()),
                snippet: Some(
                    "Current weather in Cheyenne, Wyoming: temperature 30 F, humidity 68%, wind 11 mph."
                        .to_string(),
                ),
                domain: Some("weather-atlas.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        "what's the weather right now",
        2,
        &bundle,
        Some("Anderson, SC"),
    );

    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("Anderson") || url.contains("anderson")),
        "expected localized candidate to remain: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("wyoming-usa/cheyenne")),
        "expected non-local candidate to be pruned: {:?}",
        plan.candidate_urls
    );
}

#[test]
fn web_pipeline_selected_source_quality_metrics_track_local_business_anchor_and_locality() {
    let selected_urls = vec![
        "https://www.carminesnyc.com/locations/upper-west-side/menus/dinner".to_string(),
        "https://www.frankrestaurant.com/menu".to_string(),
        "https://www.lartusi.com/menus/dinner".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("Carmine's Upper West Side Dinner Menu".to_string()),
            excerpt:
                "Italian restaurant in New York, NY with family-style pasta, chicken parm and seafood."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Frank Restaurant Dinner Menu".to_string()),
            excerpt:
                "East Village Italian restaurant in New York, NY serving pasta, veal and house specialties."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some("L'Artusi Dinner Menu".to_string()),
            excerpt:
                "West Village Italian restaurant in New York, NY with handmade pasta and seasonal dishes."
                    .to_string(),
        },
    ];

    let (
        total_sources,
        compatible_sources,
        locality_compatible_sources,
        distinct_domains,
        low_priority_sources,
        quality_floor_met,
        low_priority_urls,
    ) = selected_source_quality_metrics_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &selected_urls,
        &source_hints,
        Some("New York, NY"),
    );

    assert_eq!(total_sources, 3);
    assert_eq!(compatible_sources, 3);
    assert_eq!(locality_compatible_sources, 3);
    assert_eq!(distinct_domains, 3);
    assert_eq!(low_priority_sources, 0);
    assert!(quality_floor_met);
    assert!(low_priority_urls.is_empty());
}

#[test]
fn web_pipeline_pre_read_plan_rejects_community_thread_candidates_for_price_lookup() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("bitcoin price".to_string()),
        url: Some("https://duckduckgo.com/?q=bitcoin+price".to_string()),
        sources: vec![
            WebSource {
                source_id: "reddit-thread".to_string(),
                rank: Some(1),
                url: "https://www.reddit.com/r/CryptoCurrency/comments/14zq3b4/why_is_the_bitcoin_price_falling_what_is_the/"
                    .to_string(),
                title: Some("Why is the Bitcoin price falling?".to_string()),
                snippet: Some(
                    "Current BTC price is $68,123, but this thread is community speculation about where it goes next."
                        .to_string(),
                ),
                domain: Some("reddit.com".to_string()),
            },
            WebSource {
                source_id: "market-surface".to_string(),
                rank: Some(2),
                url: "https://www.example.com/markets/bitcoin-price".to_string(),
                title: Some("Bitcoin price".to_string()),
                snippet: Some("BTC price today is $68,123.45 as of 14:32 UTC.".to_string()),
                domain: Some("example.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        "What's the current price of Bitcoin?",
        2,
        &bundle,
        None,
    );

    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("reddit.com")),
        "community-thread surfaces should not remain in grounded snapshot candidate inventory: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("/markets/bitcoin-price")),
        "expected structurally resolvable market surface to remain: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.requires_constraint_search_probe,
        "single-snapshot lookup should still request probe recovery when the distinct-source floor is unmet: {:?}",
        plan
    );
}

#[test]
fn web_pipeline_pre_read_plan_requires_probe_when_only_community_threads_remain() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("bitcoin price".to_string()),
        url: Some("https://duckduckgo.com/?q=bitcoin+price".to_string()),
        sources: vec![WebSource {
            source_id: "reddit-thread".to_string(),
            rank: Some(1),
            url: "https://www.reddit.com/r/CryptoCurrency/comments/14zq3b4/why_is_the_bitcoin_price_falling_what_is_the/"
                .to_string(),
            title: Some("Why is the Bitcoin price falling?".to_string()),
            snippet: Some(
                "Current BTC price is $68,123, but this thread is community speculation about where it goes next."
                    .to_string(),
            ),
            domain: Some("reddit.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        "What's the current price of Bitcoin?",
        2,
        &bundle,
        None,
    );

    assert!(
        plan.candidate_urls.is_empty(),
        "weak community-thread inventory should be rejected instead of read directly: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.requires_constraint_search_probe,
        "empty grounded snapshot inventory should trigger structural probe recovery"
    );
    assert!(
        !plan.probe_source_hints.is_empty(),
        "probe recovery should retain the rejected discovery hints as evidence evidence"
    );
}

#[test]
fn web_pipeline_pre_read_plan_retains_rejected_locality_hints_for_probe_recovery() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:ddg".to_string(),
        query: Some("best-reviewed Italian restaurants near me".to_string()),
        url: Some(
            "https://duckduckgo.com/?q=best-reviewed+Italian+restaurants+near+me".to_string(),
        ),
        sources: vec![WebSource {
            source_id: "reddit-italian".to_string(),
            rank: Some(1),
            url: "https://www.reddit.com/r/Italian/".to_string(),
            title: Some("r/Italian".to_string()),
            snippet: Some("Italian language and culture discussion community.".to_string()),
            domain: Some("reddit.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &bundle,
        Some("Anderson, SC"),
    );

    assert!(plan.candidate_urls.is_empty());
    assert!(plan.requires_constraint_search_probe);
    assert_eq!(plan.probe_source_hints.len(), 1);
}

#[test]
fn web_pipeline_headline_pre_read_plan_prunes_roundup_pages_when_article_candidates_exist() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:google-news-rss".to_string(),
        query: Some("today top news headlines".to_string()),
        url: Some("https://news.google.com/rss/search?q=today+top+news+headlines".to_string()),
        sources: vec![
            WebSource {
                source_id: "today-story".to_string(),
                rank: Some(1),
                url: "https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092".to_string(),
                title: Some(
                    "High School Teacher Reveals The 1 Classroom Rule She No Longer Enforces After 25 Years".to_string(),
                ),
                snippet: Some(
                    "A Texas teacher says some classroom rules stop helping students after 25 years in the classroom.".to_string(),
                ),
                domain: Some("today.com".to_string()),
            },
            WebSource {
                source_id: "allafrica-wrapper".to_string(),
                rank: Some(2),
                url: "https://news.google.com/rss/articles/CBMiW0FVX3lxTFBGbTBYWUpMa3NqcF9PUUFFc1pyMGQybUpPTUNqMENMaFFJb3BONVJOS3RQNUZ6UGdHQUZvcXF0elE3MXhYbTlkeEhSTjZCX2xDeERYQkUwN3hySkk?oc=5".to_string(),
                title: Some(
                    "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com".to_string(),
                ),
                snippet: Some(
                    "Hospitals and supply routes were hit as conflict spread in Kordofan.".to_string(),
                ),
                domain: Some("news.google.com".to_string()),
            },
            WebSource {
                source_id: "roundup".to_string(),
                rank: Some(3),
                url: "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/".to_string(),
                title: Some(
                    "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
                ),
                snippet: Some(
                    "Daily school assembly roundup with thought of the day and headline digest.".to_string(),
                ),
                domain: Some("sundayguardianlive.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let plan = pre_read_candidate_plan_from_bundle_with_locality_hint(
        "Tell me today's top news headlines.",
        2,
        &bundle,
        None,
    );

    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("school-assembly-news-headlines")),
        "expected low-priority roundup to be pruned when higher-quality candidates exist: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("news.google.com/rss/articles/")),
        "expected at least one article-capable read target to remain: {:?}",
        plan.candidate_urls
    );
}

#[test]
fn web_pipeline_selected_source_quality_metrics_accept_entity_diverse_same_domain_sources() {
    let selected_urls = vec![
        "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/".to_string(),
        "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/".to_string(),
        "https://www.restaurantji.com/sc/anderson/olive-garden-/".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("Brothers Italian Cuisine".to_string()),
            excerpt:
                "Italian restaurant in Anderson, SC with stromboli, manicotti and garlic knots on the menu."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Public Well Cafe and Pizza".to_string()),
            excerpt:
                "Italian restaurant in Anderson, SC with pizza, pasta and dinner menu specials."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some("Olive Garden Italian Restaurant".to_string()),
            excerpt:
                "Italian restaurant in Anderson, SC with soup, salad, breadsticks and pasta menu classics."
                    .to_string(),
        },
    ];

    let (
        total_sources,
        compatible_sources,
        locality_compatible_sources,
        distinct_domains,
        low_priority_sources,
        quality_floor_met,
        low_priority_urls,
    ) = selected_source_quality_metrics_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &selected_urls,
        &source_hints,
        Some("Anderson, SC"),
    );

    assert_eq!(total_sources, 3);
    assert_eq!(compatible_sources, 3);
    assert_eq!(locality_compatible_sources, 3);
    assert_eq!(distinct_domains, 1);
    assert_eq!(low_priority_sources, 0);
    assert!(quality_floor_met);
    assert!(low_priority_urls.is_empty());
}

#[test]
fn web_pipeline_pre_read_action_count_prefers_single_seed_when_direct_inventory_is_sparse() {
    let source_hints = vec![
        PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            title: Some("Top-rated Anderson, SC Italian Restaurants".to_string()),
            excerpt:
                "Restaurant directory listing in Anderson, SC with reviews, ratings and menus."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurants-g30051-Anderson_South_Carolina.html"
                .to_string(),
            title: Some("Best Italian Restaurants in Anderson, SC".to_string()),
            excerpt:
                "Ranked restaurant guide for Anderson, SC with review counts and cuisine filters."
                    .to_string(),
        },
    ];

    let preferred_count = preferred_pre_read_action_count_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &source_hints,
        Some("Anderson, SC"),
    );

    assert_eq!(preferred_count, 1);
}

#[test]
fn web_pipeline_pre_read_candidate_plan_accepts_time_sensitive_metric_pages_with_metadata_quotes() {
    let query = "What's the current price of Bitcoin?";
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:search:aggregate:price-snapshot".to_string(),
        query: Some("current Bitcoin price".to_string()),
        url: Some("https://www.coindesk.com/price/bitcoin".to_string()),
        sources: vec![
            WebSource {
                source_id: "coindesk".to_string(),
                rank: Some(1),
                url: "https://www.coindesk.com/price/bitcoin".to_string(),
                title: Some(
                    "Bitcoin price today, BTC to USD live price, marketcap and chart | CoinDesk"
                        .to_string(),
                ),
                snippet: Some(
                    "The price of Bitcoin (BTC) is $68,214.99 today as of Mar 6, 2026, 2:25 pm EST."
                        .to_string(),
                ),
                domain: Some("coindesk.com".to_string()),
            },
            WebSource {
                source_id: "crypto-news".to_string(),
                rank: Some(2),
                url: "https://crypto.news/price/bitcoin/".to_string(),
                title: Some("Bitcoin price: BTC to USD, chart & market stats".to_string()),
                snippet: Some(
                    "Get the latest Bitcoin price in USD, currently at 68,191.00, live chart, 24h stats, market cap, trading volume, and real-time updates.".to_string(),
                ),
                domain: Some("crypto.news".to_string()),
            },
            WebSource {
                source_id: "coincodex".to_string(),
                rank: Some(3),
                url: "https://www.coincodex.com/crypto/bitcoin/".to_string(),
                title: Some(
                    "Bitcoin Price: Live BTC/USD Rate, Market Cap & BTC Price Chart | CoinCodex"
                        .to_string(),
                ),
                snippet: Some(
                    "Bitcoin price today is $68,026 with a trading volume of $56.53B and market cap of $1.36T. BTC price decreased -4.1% in the last 24 hours.".to_string(),
                ),
                domain: Some("coincodex.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let plan = pre_read_candidate_plan_from_bundle_with_locality_hint(query, 2, &bundle, None);

    assert!(
        plan.candidate_urls.len() >= 2,
        "expected at least 2 direct-read candidates, got {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url == "https://www.coindesk.com/price/bitcoin"),
        "expected CoinDesk price page to remain admissible: {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url == "https://www.coincodex.com/crypto/bitcoin/"),
        "expected CoinCodex price page to be admissible: {:?}",
        plan.candidate_urls
    );
}

#[test]
fn web_pipeline_selected_source_quality_metrics_reject_non_local_restaurant_inventory() {
    let selected_urls = vec![
        "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
            .to_string(),
        "https://www.tripadvisor.com.au/Restaurants-g30090-c26-Anderson_South_Carolina.html"
            .to_string(),
        "https://www.sirved.com/city/anderson-south_carolina-usa/all/Italian-restaurants"
            .to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("Best Italian Restaurants in Anderson, South Carolina".to_string()),
            excerpt:
                "Review listings for Anderson, South Carolina Italian restaurants with rankings and menus."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Top-rated Anderson, SC Italian Restaurants".to_string()),
            excerpt:
                "Tripadvisor restaurant rankings for Anderson, SC with review counts and cuisine filters."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some("Anderson Italian Restaurants".to_string()),
            excerpt:
                "Italian restaurants near Anderson, South Carolina with menus and ratings."
                    .to_string(),
        },
    ];

    let (
        total_sources,
        compatible_sources,
        locality_compatible_sources,
        distinct_domains,
        _low_priority_sources,
        quality_floor_met,
        _low_priority_urls,
    ) = selected_source_quality_metrics_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &selected_urls,
        &source_hints,
        Some("New York, NY"),
    );
    let projection = build_query_constraint_projection_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &source_hints,
        Some("New York, NY"),
    );
    let direct_compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        &selected_urls[0],
        source_hints[0].title.as_deref().unwrap_or_default(),
        &source_hints[0].excerpt,
    );
    let source_locality = source_locality_tokens(
        &selected_urls[0],
        source_hints[0].title.as_deref().unwrap_or_default(),
        &source_hints[0].excerpt,
    );

    assert_eq!(total_sources, 3);
    assert!(
        projection.query_facets.grounded_external_required,
        "expected grounded external requirement for local restaurant lookup"
    );
    assert!(
        !direct_compatibility.locality_compatible,
        "source_locality={:?} query_locality={:?} grounded_external_required={} locality_scope={:?}",
        source_locality,
        projection.locality_tokens,
        projection.query_facets.grounded_external_required,
        projection.locality_scope
    );
    assert_eq!(
        compatible_sources, 0,
        "locality_scope={:?} locality_tokens={:?}",
        projection.locality_scope, projection.locality_tokens
    );
    assert_eq!(
        locality_compatible_sources, 0,
        "locality_scope={:?} locality_tokens={:?}",
        projection.locality_scope, projection.locality_tokens
    );
    assert_eq!(distinct_domains, 3);
    assert!(!quality_floor_met);
}

#[test]
fn web_pipeline_projection_candidate_collection_prunes_low_priority_sources_when_floor_is_met() {
    let selected_urls = vec![
        "https://www.carminesnyc.com/locations/upper-west-side/menus/dinner".to_string(),
        "https://www.frankrestaurant.com/menu".to_string(),
        "https://www.lartusi.com/menus/dinner".to_string(),
        "https://support.opensea.io/en/articles/8866943-create-your-account-with-an-email"
            .to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("Carmine's Upper West Side Dinner Menu".to_string()),
            excerpt:
                "Italian restaurant in New York, NY with family-style pasta, chicken parm and seafood."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Frank Restaurant Dinner Menu".to_string()),
            excerpt:
                "East Village Italian restaurant in New York, NY serving pasta, veal and house specialties."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some("L'Artusi Dinner Menu".to_string()),
            excerpt:
                "West Village Italian restaurant in New York, NY with handmade pasta and seasonal dishes."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[3].clone(),
            title: Some("Create your account with an email".to_string()),
            excerpt: "OpenSea Help Center support article for account creation.".to_string(),
        },
    ];

    let collected = collect_projection_candidate_urls_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &selected_urls,
        &source_hints,
        10,
        3,
        &BTreeSet::new(),
        Some("New York, NY"),
    );

    assert_eq!(collected.len(), 3);
    assert!(
        collected
            .iter()
            .all(|url| !url.contains("opensea.io") && !url.contains("/support")),
        "expected low-priority support URL to be pruned: {:?}",
        collected
    );
}

#[test]
fn web_pipeline_pre_read_preserves_location_weather_candidates_under_grounded_constraints() {
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "edge:bing:http".to_string(),
        query: Some("what's the weather right now in anderson sc".to_string()),
        url: Some("https://www.bing.com/search?q=current+weather+anderson+sc".to_string()),
        sources: vec![
            WebSource {
                source_id: "weather-atlas".to_string(),
                rank: Some(1),
                url: "https://www.weather-atlas.com/en/south-carolina-usa/anderson".to_string(),
                title: Some("Weather today - Anderson, SC".to_string()),
                snippet: Some(
                    "Current weather and hourly forecast page for Anderson, SC.".to_string(),
                ),
                domain: Some("weather-atlas.com".to_string()),
            },
            WebSource {
                source_id: "weather-com".to_string(),
                rank: Some(2),
                url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
                title: Some(
                    "Weather Forecast and Conditions for Anderson, South Carolina".to_string(),
                ),
                snippet: Some(
                    "Current weather conditions and local radar in Anderson, South Carolina."
                        .to_string(),
                ),
                domain: Some("weather.com".to_string()),
            },
            WebSource {
                source_id: "bing-hub".to_string(),
                rank: Some(3),
                url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
                title: Some("Bing".to_string()),
                snippet: Some("Search results page.".to_string()),
                domain: Some("bing.com".to_string()),
            },
            WebSource {
                source_id: "rapidtables".to_string(),
                rank: Some(4),
                url: "https://www.rapidtables.com/math/symbols/Basic_Math_Symbols.html".to_string(),
                title: Some("Math Symbols List".to_string()),
                snippet: Some("Basic math symbols and examples.".to_string()),
                domain: Some("rapidtables.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    let plan = pre_read_candidate_plan_from_bundle(
        "What's the weather right now in Anderson, SC?",
        2,
        &bundle,
    );
    assert!(
        !plan.candidate_urls.is_empty(),
        "grounded weather candidates should remain available for read acquisition: {:?}",
        plan
    );
    assert!(
        plan.candidate_urls
            .iter()
            .any(|url| url.contains("anderson")),
        "expected Anderson-localized weather candidates, got {:?}",
        plan.candidate_urls
    );
    assert!(
        plan.candidate_urls
            .iter()
            .all(|url| !url.contains("bing.com/search") && !url.contains("rapidtables.com")),
        "search hubs and unrelated pages should be pruned: {:?}",
        plan.candidate_urls
    );
}

#[test]
fn web_pipeline_projection_candidate_url_allowed_requires_structural_detail_markers() {
    assert!(
        !projection_candidate_url_allowed("https://www.example.com/menu"),
        "shallow menu hubs must not be treated as detail documents"
    );
    assert!(
        !projection_candidate_url_allowed("https://www.example.com/us/restaurant/anderson-sc"),
        "taxonomy paths with restaurant tokens alone must not be treated as detail documents"
    );
    assert!(
        projection_candidate_url_allowed(
            "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
        ),
        "detail slugs with structural depth should remain admissible"
    );
}
