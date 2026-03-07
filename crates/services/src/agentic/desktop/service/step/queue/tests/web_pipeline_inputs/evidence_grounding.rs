use super::*;

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
        "probe recovery should retain the rejected discovery hints as evidence receipts"
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
fn web_pipeline_discovery_affordances_classify_local_business_listing_as_seed_read() {
    let source_hints = vec![PendingSearchReadSummary {
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        title: Some("Top-rated Anderson, SC Italian Restaurants".to_string()),
        excerpt: "Restaurant directory listing in Anderson, SC with reviews, ratings and menus."
            .to_string(),
    }];

    let affordances = retrieval_affordances_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &source_hints,
        Some("Anderson, SC"),
        &source_hints[0].url,
        source_hints[0].title.as_deref().unwrap_or_default(),
        &source_hints[0].excerpt,
    );

    assert!(
        affordances.contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead),
        "expected discovery seed affordance for listing page: {:?}",
        affordances
    );
    assert!(
        !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead),
        "listing page should not be treated as a direct citation read: {:?}",
        affordances
    );
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
fn web_pipeline_local_business_targets_can_be_observed_from_direct_detail_pages() {
    let targets = local_business_target_names_from_sources(
        &[
            PendingSearchReadSummary {
                url: "https://www.tripadvisor.com/Restaurant_Review-g60763-d25369085-Reviews-Marcellino_Restaurant-New_York_City_New_York.html".to_string(),
                title: Some(
                    "MARCELLINO RESTAURANT, New York City - Menu, Prices & Restaurant Reviews"
                        .to_string(),
                ),
                excerpt: "Italian restaurant in New York City with menu, prices and reviews."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.opentable.com/r/don-angie-new-york".to_string(),
                title: Some("Don Angie Restaurant - New York, NY - OpenTable".to_string()),
                excerpt: "Italian restaurant in New York, NY with reservations and menu details."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://ny.eater.com/maps/best-new-york-restaurants-38-map".to_string(),
                title: Some("The 38 Best Restaurants in New York City - Eater New York".to_string()),
                excerpt: "Where to eat right now across New York City neighborhoods.".to_string(),
            },
        ],
        Some("New York, NY"),
        3,
    );

    assert_eq!(
        targets,
        vec![
            "MARCELLINO RESTAURANT".to_string(),
            "Don Angie Restaurant".to_string(),
        ]
    );
}

#[test]
fn web_pipeline_local_business_targets_fall_back_to_detail_slug_when_title_is_host_only() {
    let targets = local_business_target_names_from_sources(
        &[PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurant_Review-g60763-d478005-Reviews-Pepe_Giallo-New_York_City_New_York.html".to_string(),
            title: Some("tripadvisor.com".to_string()),
            excerpt: "Tripadvisor | source_url=https://www.tripadvisor.com".to_string(),
        }],
        Some("New York, NY"),
        3,
    );

    assert_eq!(targets, vec!["Pepe Giallo".to_string()]);
}

#[test]
fn web_pipeline_local_business_targets_ignore_metadata_article_slugs() {
    let targets = local_business_target_names_from_sources(
        &[PendingSearchReadSummary {
            url: "https://m.economictimes.com/news/international/us/top-italian-restaurants-in-new-york-try-out-the-best-cuisines-from-their-menu-check-opening-and-closing-timings-and-location/articleshow/123920925.cms".to_string(),
            title: Some(
                "Top Italian restaurants in New York, try out the best cuisines from their menu, check opening and closing - The Economic Times"
                    .to_string(),
            ),
            excerpt: "Top Italian restaurants in New York, try out the best cuisines from their menu, check opening and closing.".to_string(),
        }],
        Some("New York, NY"),
        3,
    );

    assert!(
        targets.is_empty(),
        "expected metadata article slug to be ignored: {:?}",
        targets
    );
}

#[test]
fn web_pipeline_local_business_targets_ignore_multi_item_listing_pages() {
    let targets = local_business_target_names_from_sources(
        &[PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
                .to_string(),
            title: Some("Restaurants Anderson South Carolina".to_string()),
            excerpt:
                "Restaurants ranked by how well they match your selections and traveler reviews."
                    .to_string(),
        }],
        Some("Anderson, SC"),
        3,
    );

    assert!(
        targets.is_empty(),
        "expected multi-item listing page to be ignored as a local-business target: {:?}",
        targets
    );
}

#[test]
fn web_pipeline_local_business_candidate_filter_rejects_language_learning_topic_drift() {
    let selected_urls = vec![
        "https://www.eater.com/nyc/italian-restaurant-reviews".to_string(),
        "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc".to_string(),
        "https://www.nytimes.com/section/dining/italian-restaurants-nyc".to_string(),
        "https://storylearning.com/learn/italian/italian-tips/basic-italian-phrases".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("The Best Italian Restaurants in NYC".to_string()),
            excerpt:
                "Restaurant reviews and dining guide for the best Italian restaurants in New York, NY."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Best Italian Restaurants in NYC".to_string()),
            excerpt:
                "Menus, reviews and ratings for Italian restaurants in New York, NY."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some("Italian Restaurants NYC".to_string()),
            excerpt:
                "Dining coverage of Italian restaurants in New York, NY with review context."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[3].clone(),
            title: Some("Basic Italian Phrases".to_string()),
            excerpt:
                "Learn Italian phrases, grammar and language basics for beginners."
                    .to_string(),
        },
    ];

    let filtered = collect_projection_candidate_urls_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &selected_urls,
        &source_hints,
        4,
        3,
        &BTreeSet::new(),
        Some("New York, NY"),
    );

    assert!(
        filtered
            .iter()
            .all(|url| !url.contains("storylearning.com/learn/italian")),
        "expected language-learning topic drift to be rejected: {:?}",
        filtered
    );
    assert!(
        filtered.len() >= 3,
        "expected restaurant comparison candidates to remain available: {:?}",
        filtered
    );
}

#[test]
fn web_pipeline_local_business_candidate_filter_rejects_generic_root_domains() {
    let selected_urls = vec![
        "https://www.eater.com/nyc/2023/10/02/best-italian-restaurants-new-york".to_string(),
        "https://www.zagat.com/best-italian-restaurants-in-new-york".to_string(),
        "https://www.tripadvisor.com".to_string(),
        "https://www.lawlessitalian.com/".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("Best Italian Restaurants in New York".to_string()),
            excerpt:
                "Restaurant reviews and dining guide for the best Italian restaurants in New York, NY."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Best Italian Restaurants in New York".to_string()),
            excerpt:
                "Ratings and menus for the best Italian restaurants in New York, NY."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some("Tripadvisor: Best Italian Restaurants in New York".to_string()),
            excerpt:
                "Tripadvisor rankings and ratings for Italian restaurants in New York, NY."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[3].clone(),
            title: Some("Lawless Italian - Free Italian lessons and language tools".to_string()),
            excerpt:
                "Learn Italian phrases, grammar and language basics for beginners."
                    .to_string(),
        },
    ];

    let filtered = collect_projection_candidate_urls_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &selected_urls,
        &source_hints,
        4,
        3,
        &BTreeSet::new(),
        Some("New York, NY"),
    );

    assert!(
        filtered
            .iter()
            .all(|url| url != "https://www.tripadvisor.com"),
        "expected generic aggregator root to be rejected: {:?}",
        filtered
    );
    assert!(
        filtered
            .iter()
            .all(|url| url != "https://www.lawlessitalian.com/"),
        "expected generic topical root to be rejected: {:?}",
        filtered
    );
}

#[test]
fn web_pipeline_local_business_candidate_filter_rejects_locality_wide_listing_pages_as_direct_citations(
) {
    let selected_urls = vec![
        "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
            .to_string(),
        "https://www.tripadvisor.com/Restaurant_Review-g30090-d7737743-Reviews-Red_Tomato_And_Wine_Restaurant-Anderson_South_Carolina.html"
            .to_string(),
        "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/".to_string(),
        "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/"
            .to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("Italian Restaurants in Anderson - Tripadvisor".to_string()),
            excerpt:
                "Tripadvisor traveller reviews for Italian restaurants in Anderson, South Carolina."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some(
                "RED TOMATO AND WINE RESTAURANT, Anderson - Menu, Prices & Restaurant Reviews - Tripadvisor"
                    .to_string(),
            ),
            excerpt:
                "Italian restaurant in Anderson, SC with menu, prices and restaurant reviews."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some(
                "Public Well Cafe and Pizza, Anderson - Menu, Reviews (205), Photos (34) - Restaurantji"
                    .to_string(),
            ),
            excerpt:
                "Italian restaurant in Anderson, SC with pizza, pasta and 205 reviews."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[3].clone(),
            title: Some(
                "Dolce Vita Italian Bistro and Pizzeria, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                    .to_string(),
            ),
            excerpt:
                "Italian restaurant in Anderson, SC with pasta, pizza and 278 reviews."
                    .to_string(),
        },
    ];

    let filtered = collect_projection_candidate_urls_with_locality_hint(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        3,
        &selected_urls,
        &source_hints,
        4,
        3,
        &BTreeSet::new(),
        Some("Anderson, SC"),
    );

    assert!(
        filtered
            .iter()
            .all(|url| !url.contains("/Restaurants-g30090-c26-Anderson_South_Carolina")),
        "expected locality-wide listing page to stay discovery-only: {:?}",
        filtered
    );
    assert!(
        filtered.iter().any(|url| {
            url.contains("Red_Tomato_And_Wine_Restaurant")
                || url.contains("/public-well-cafe-and-pizza-/")
                || url.contains("/dolce-vita-italian-bistro-and-pizzeria-/")
        }),
        "expected at least one per-restaurant detail page to remain selectable: {:?}",
        filtered
    );
}

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
fn web_pipeline_headline_candidate_collection_reorders_payload_noise_behind_actionable_articles() {
    let selected_urls = vec![
        "https://sentinelcolorado.com/nation-world/world/friday-news-in-a-rush-top-headlines-in-todays-newsminute-video-257/".to_string(),
        "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026".to_string(),
        "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "FRIDAY NEWS IN A RUSH: Top headlines in today's NewsMinute video - Sentinel Colorado"
                    .to_string(),
            ),
            excerpt: "Top world headlines and daily roundup.".to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Top news headlines for Thursday, March 5, 2026".to_string()),
            excerpt: "Local roundup of the day's top headlines.".to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            excerpt:
                "Daily school assembly roundup with thought of the day and headline digest."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092"
                .to_string(),
            title: Some(
                "High School Teacher Reveals The 1 Classroom Rule She No Longer Enforces After 25 Years".to_string(),
            ),
            excerpt:
                "A Texas teacher says some classroom rules stop helping students after 25 years in the classroom."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384"
                .to_string(),
            title: Some(
                "Today in Africa — Mar 6, 2026: WAFCON Postponed, Uganda Evacuates 43 Students From Iran".to_string(),
            ),
            excerpt:
                "Uganda evacuated 43 students from Iran while WAFCON was postponed, according to today's regional report."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://news.google.com/rss/articles/CBMiW0FVX3lxTFBGbTBYWUpMa3NqcF9PUUFFc1pyMGQybUpPTUNqMENMaFFJb3BONVJOS3RQNUZ6UGdHQUZvcXF0elE3MXhYbTlkeEhSTjZCX2xDeERYQkUwN3hySkk?oc=5".to_string(),
            title: Some(
                "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com".to_string(),
            ),
            excerpt:
                "Hospitals and supply routes were hit as conflict spread in Kordofan."
                    .to_string(),
        },
    ];

    let collected = collect_projection_candidate_urls_with_locality_hint(
        "Tell me today's top news headlines.",
        3,
        &selected_urls,
        &source_hints,
        6,
        3,
        &BTreeSet::new(),
        None,
    );

    assert!(
        collected
            .iter()
            .take(3)
            .any(|url| url.contains("today.com/parents/family/viral-teacher-tiktok-cursing-rule")),
        "expected actionable article candidate to outrank payload-selected roundup noise: {:?}",
        collected
    );
    assert!(
        collected
            .iter()
            .take(3)
            .any(|url| url.contains("okayafrica.com/today-in-africa-mar-6-2026")),
        "expected additional actionable article candidate to remain in the leading set: {:?}",
        collected
    );
    assert!(
        collected
            .iter()
            .take(3)
            .all(|url| !url.contains("school-assembly-news-headlines")),
        "expected low-priority roundup page to stay behind actionable articles: {:?}",
        collected
    );
}

#[test]
fn web_pipeline_query_grounding_excerpt_accepts_local_restaurant_menu_descriptions() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.";
    let title = "Carmine's Upper West Side Dinner Menu";
    let excerpt = "Family-style Italian menu in New York, NY with spaghetti and meatballs, chicken parmigiana, lasagna and seafood pasta.";
    let projection =
        build_query_constraint_projection_with_locality_hint(query, 3, &[], Some("New York, NY"));
    let source_tokens = source_anchor_tokens(
        "https://www.carminesnyc.com/locations/upper-west-side/menus/dinner",
        title,
        excerpt,
    );

    assert!(
        excerpt_has_query_grounding_signal(
            query,
            3,
            "https://www.carminesnyc.com/locations/upper-west-side/menus/dinner",
            title,
            excerpt,
        ),
        "query_tokens={:?} native_tokens={:?} source_tokens={:?}",
        projection.query_tokens,
        projection.query_native_tokens,
        source_tokens
    );
}

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

#[test]
fn web_pipeline_bundle_success_retries_with_requested_url_when_document_url_fails() {
    let requested_url = "https://weather.com/weather/today/l/Anderson+SC";
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=current+weather+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt: "Current weather in Anderson, SC: temperature 62 F, humidity 42%, wind 4 mph."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some("https://example.com/redirect".to_string()),
        sources: vec![WebSource {
            source_id: "source:redirect".to_string(),
            rank: None,
            url: "https://example.com/redirect".to_string(),
            title: Some("Redirect landing page".to_string()),
            snippet: Some("Navigation links and policy text.".to_string()),
            domain: Some("example.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:redirect".to_string(),
            url: "https://example.com/redirect".to_string(),
            title: Some("Redirect landing page".to_string()),
            content_text: "Navigation and legal terms. Sign in to continue.".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .to_ascii_lowercase()
            .contains("temperature"),
        "expected fallback requested URL to retain compatible hint payload"
    );
}

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

#[test]
fn web_pipeline_single_snapshot_current_price_rejects_non_quote_price_page_excerpt() {
    let requested_url = "https://crypto.com/en/price/bitcoin";
    let retrieval_contract = WebRetrievalContract {
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 1,
        citation_count_min: 1,
        structured_record_preferred: true,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: false,
        discovery_surface_required: false,
        entity_diversity_required: false,
        scalar_measure_required: true,
        browser_fallback_allowed: true,
        ..WebRetrievalContract::default()
    };
    let mut pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://search.brave.com/search?q=current+bitcoin+price".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            excerpt: "80% in the last 24 hours".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:crypto-price".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            snippet: Some("80% in the last 24 hours".to_string()),
            domain: Some("crypto.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:crypto-price".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            content_text: "80% in the last 24 hours".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "current price snapshot contracts should reject non-quote percentage pages as successful evidence"
    );
}

#[test]
fn web_pipeline_single_snapshot_current_price_prefers_quote_metric_excerpt_when_available() {
    let requested_url = "https://crypto.com/en/price/bitcoin";
    let retrieval_contract = WebRetrievalContract {
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 1,
        citation_count_min: 1,
        structured_record_preferred: true,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: false,
        discovery_surface_required: false,
        entity_diversity_required: false,
        scalar_measure_required: true,
        browser_fallback_allowed: true,
        ..WebRetrievalContract::default()
    };
    let mut pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(retrieval_contract),
        url: "https://search.brave.com/search?q=current+bitcoin+price".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            excerpt: "80% in the last 24 hours".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:crypto-price".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            snippet: Some("80% in the last 24 hours".to_string()),
            domain: Some("crypto.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:crypto-price".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International"
                    .to_string(),
            ),
            content_text:
                "80% in the last 24 hours. Bitcoin price right now: $86,743.63 USD as of 17:23 UTC."
                    .to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0].excerpt.contains("$86,743"),
        "expected quote-bearing metric excerpt to win over non-price percentage text: {:?}",
        pending.successful_reads
    );
}

#[test]
fn current_price_query_grounding_excerpt_requires_price_quote_payload() {
    let retrieval_contract = WebRetrievalContract {
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 1,
        citation_count_min: 1,
        structured_record_preferred: true,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: false,
        discovery_surface_required: false,
        entity_diversity_required: false,
        scalar_measure_required: true,
        browser_fallback_allowed: true,
        ..WebRetrievalContract::default()
    };
    let query = "What's the current price of Bitcoin?";
    let url = "https://crypto.com/en/price/bitcoin";
    let title = "Bitcoin (BTC) Price Today: BTC Live Price, Charts, News - Crypto.com International";
    assert!(!excerpt_has_query_grounding_signal_with_contract(
        Some(&retrieval_contract),
        query,
        1,
        url,
        title,
        "80% in the last 24 hours",
    ));
    assert!(excerpt_has_query_grounding_signal_with_contract(
        Some(&retrieval_contract),
        query,
        1,
        url,
        title,
        "Bitcoin price right now: $86,743.63 USD as of 17:23 UTC.",
    ));
}

#[test]
fn web_pipeline_headline_bundle_success_ignores_cross_domain_noise() {
    let requested_url =
        "https://www.cbsnews.com/news/us-israel-attack-iran-world-reaction-to-war-middle-east/";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.google.com/search?q=today+top+news+headlines&tbm=nws".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "As the U.S. and Israel attack Iran, governments around the world stress risks of new war in the Middle East"
                    .to_string(),
            ),
            excerpt: "Updated on: March 1, 2026 / 7:19 AM EST / CBS News.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![
            WebSource {
                source_id: "source:cbs".to_string(),
                rank: None,
                url: requested_url.to_string(),
                title: Some("CBS News".to_string()),
                snippet: Some("CBS story snippet.".to_string()),
                domain: Some("cbsnews.com".to_string()),
            },
            WebSource {
                source_id: "source:noise".to_string(),
                rank: None,
                url: "https://www.today.com/popculture/awards/where-to-watch-naacp-image-awards-2026-rcna260446"
                    .to_string(),
                title: Some("Where to Watch the 2026 NAACP Image Awards".to_string()),
                snippet: Some("Unrelated entertainment story.".to_string()),
                domain: Some("today.com".to_string()),
            },
        ],
        source_observations: vec![],
        documents: vec![
            WebDocument {
                source_id: "source:cbs".to_string(),
                url: requested_url.to_string(),
                title: Some("CBS News".to_string()),
                content_text: "Article content from CBS.".to_string(),
                content_hash: "hash-cbs".to_string(),
                quote_spans: vec![],
            },
            WebDocument {
                source_id: "source:noise".to_string(),
                url: "https://www.today.com/popculture/awards/where-to-watch-naacp-image-awards-2026-rcna260446"
                    .to_string(),
                title: Some("Noise story".to_string()),
                content_text: "Article content from unrelated domain.".to_string(),
                content_hash: "hash-noise".to_string(),
                quote_spans: vec![],
            },
        ],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(
        pending.successful_reads.len(),
        1,
        "headline ingestion should only record evidence bound to the requested read URL"
    );
    assert_eq!(pending.successful_reads[0].url, requested_url);
    assert!(
        !pending.successful_reads[0].url.contains("today.com"),
        "cross-domain bundle noise must not be recorded as a successful read"
    );
}

#[test]
fn web_pipeline_bundle_success_marks_human_challenge_pages_blocked() {
    let requested_url =
        "https://www.tripadvisor.com/Restaurant_Review-g60763-d26557158-Reviews-Roscioli-New_York_City_New_York.html";
    let mut pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=Roscioli+restaurant+menu+New+York+NY".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("tripadvisor.com".to_string()),
            excerpt: "Please enable JS and disable any ad blocker to continue.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:tripadvisor".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some("tripadvisor.com".to_string()),
            snippet: Some("Please enable JS and disable any ad blocker to continue.".to_string()),
            domain: Some("tripadvisor.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:tripadvisor".to_string(),
            url: requested_url.to_string(),
            title: Some("tripadvisor.com".to_string()),
            content_text:
                "Please enable JS and disable any ad blocker var dd={'rt':'c','cid':'token'}"
                    .to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "challenge pages should not be recorded as successful reads"
    );
    assert_eq!(pending.blocked_urls, vec![requested_url.to_string()]);
}

#[test]
fn web_pipeline_bundle_success_rejects_rate_limited_terminal_pages() {
    let requested_url =
        "https://sentinelcolorado.com/nation-world/world/friday-news-in-a-rush-top-headlines-in-todays-newsminute-video-257/";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/news/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Friday News in a Rush".to_string()),
            excerpt: "Top world headlines and daily roundup.".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:sentinel".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some("429 Too Many Requests".to_string()),
            snippet: Some("429 Too Many Requests".to_string()),
            domain: Some("sentinelcolorado.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:sentinel".to_string(),
            url: requested_url.to_string(),
            title: Some("429 Too Many Requests".to_string()),
            content_text: "429 Too Many Requests".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "rate-limited terminal pages should not be recorded as successful reads"
    );
}

#[test]
fn web_pipeline_headline_bundle_success_records_resolved_google_news_article_url() {
    let requested_url = "https://news.google.com/rss/articles/CBMiW0FVX3lxTFBGbTBYWUpMa3NqcF9PUUFFc1pyMGQybUpPTUNqMENMaFFJb3BONVJOS3RQNUZ6UGdHQUZvcXF0elE3MXhYbTlkeEhSTjZCX2xDeERYQkUwN3hySkk?oc=5";
    let resolved_url = "https://allafrica.com/stories/202603060637.html";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com"
                    .to_string(),
            ),
            excerpt: "allAfrica.com".to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(resolved_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:allafrica".to_string(),
            rank: None,
            url: resolved_url.to_string(),
            title: Some(
                "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com"
                    .to_string(),
            ),
            snippet: Some("Hospitals and supply routes in Kordofan were hit as fighting spread."
                .to_string()),
            domain: Some("allafrica.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:allafrica".to_string(),
            url: resolved_url.to_string(),
            title: Some(
                "Sudan: Hospitals, Supply Routes Hit as Conflict Spreads in Kordofan - allAfrica.com"
                    .to_string(),
            ),
            content_text: "Hospitals and supply routes in Kordofan were hit as fighting spread."
                .to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, resolved_url);
}

#[test]
fn web_pipeline_headline_hint_recovery_records_resolved_article_url_after_blocked_read() {
    let requested_url = "https://news.google.com/rss/articles/CBMiW0FVX3lxTFBGbTBYWUpMa3NqcF9PUUFFc1pyMGQybUpPTUNqMENMaFFJb3BONVJOS3RQNUZ6UGdHQUZvcXF0elE3MXhYbTlkeEhSTjZCX2xDeERYQkUwN3hySkk?oc=5";
    let resolved_url = "https://www.reuters.com/world/example-top-story-2026-03-06/";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "Trump says no deal with Iran until 'unconditional surrender' - Reuters"
                    .to_string(),
            ),
            excerpt: format!(
                "Trump said there will be no deal with Iran until 'unconditional surrender' after overnight escalation. source_url={resolved_url}"
            ),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![requested_url.to_string()],
        successful_reads: vec![],
        min_sources: 3,
    };

    let recovered = append_pending_web_success_from_hint(&mut pending, requested_url);

    assert!(
        recovered,
        "expected actionable headline hint to recover blocked read"
    );
    assert_eq!(pending.successful_reads.len(), 1);
    assert_eq!(pending.successful_reads[0].url, resolved_url);
}

#[test]
fn web_pipeline_headline_bundle_success_rejects_low_priority_roundup_pages() {
    let requested_url =
        "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/";
    let mut pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss/search?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 60_100,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            excerpt: "Daily school assembly roundup with thought of the day and headline digest."
                .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "roundup".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            snippet: Some(
                "Daily school assembly roundup with thought of the day and headline digest."
                    .to_string(),
            ),
            domain: Some("sundayguardianlive.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "roundup".to_string(),
            url: requested_url.to_string(),
            title: Some(
                "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
            ),
            content_text:
                "Daily school assembly roundup with thought of the day, top national and sports headlines."
                    .to_string(),
            content_hash: "hash-roundup".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);

    assert!(
        pending.successful_reads.is_empty(),
        "headline roundup pages should not be counted as successful article evidence"
    );
}

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

#[test]
fn web_pipeline_append_success_from_bundle_preserves_non_low_signal_read_excerpt() {
    let requested_url = "https://weather.yahoo.com/us/sc/anderson";
    let mut pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=current+weather+anderson+sc".to_string(),
        started_step: 0,
        started_at_ms: 0,
        deadline_ms: 45_000,
        candidate_urls: vec![requested_url.to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: requested_url.to_string(),
            title: Some("Anderson, SC Current Weather".to_string()),
            excerpt:
                "Current conditions at Anderson airport: Fair 35°F 2°C Humidity 38% Wind 8 mph."
                    .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };
    let bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__read".to_string(),
        backend: "edge:read:http".to_string(),
        query: None,
        url: Some(requested_url.to_string()),
        sources: vec![WebSource {
            source_id: "source:weather".to_string(),
            rank: None,
            url: requested_url.to_string(),
            title: Some("Anderson Forecast".to_string()),
            snippet: None,
            domain: Some("weather.yahoo.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "source:weather".to_string(),
            url: requested_url.to_string(),
            title: Some("Anderson Forecast".to_string()),
            content_text: "Mostly Cloudy today with a high of 61°F and a low of 45°F.".to_string(),
            content_hash: "hash".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(&mut pending, &bundle, requested_url);
    assert_eq!(pending.successful_reads.len(), 1);
    assert!(
        pending.successful_reads[0]
            .excerpt
            .contains("Mostly Cloudy today with a high of 61°F"),
        "expected read excerpt to be preserved when it has a quantitative claim"
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
