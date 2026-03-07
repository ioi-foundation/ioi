use super::*;

#[test]
fn web_pipeline_latency_budget_escalates_after_slow_attempts() {
    let pending = PendingSearchCompletion {
        query: "what's the weather right now in anderson sc".to_string(),
        query_contract: "what's the weather right now in anderson sc".to_string(),
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
            url: "https://weather.com/weather/today/l/Anderson+SC".to_string(),
            title: Some("Current weather Anderson South Carolina".to_string()),
            excerpt: "Current conditions now with temperature and humidity.".to_string(),
        }],
        attempted_urls: vec!["https://weather.com/weather/today/l/Anderson+SC".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let now_ms = 49_000;
    let required_read_ms = web_pipeline_required_read_budget_ms(&pending, now_ms);
    let required_probe_ms = web_pipeline_required_probe_budget_ms(&pending, now_ms);

    assert!(required_read_ms > 20_000);
    assert!(required_probe_ms >= required_read_ms);
    assert!(!web_pipeline_can_queue_initial_read_latency_aware(
        &pending, now_ms
    ));
    assert!(!web_pipeline_can_queue_probe_search_latency_aware(
        &pending, now_ms
    ));
    assert_eq!(
        web_pipeline_latency_pressure_label(&pending, now_ms),
        "critical"
    );
}

#[test]
fn web_pipeline_suppresses_non_actionable_excerpt_noise_in_story_sections() {
    let pending = PendingSearchCompletion {
        query: "top active cloud incidents".to_string(),
        query_contract: "top active cloud incidents".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=top+active+cloud+incidents".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://status.cloud.google.com/incidents/U39RSGjaANJXtjHpRkdq".to_string(),
            "https://azure.status.microsoft/en-us/status".to_string(),
            "https://health.aws.amazon.com/health/status".to_string(),
            "https://status.cloud.microsoft/en-us/status".to_string(),
            "https://status.salesforce.com/".to_string(),
            "https://status.datadoghq.com/".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.cloud.google.com/incidents/U39RSGjaANJXtjHpRkdq".to_string(),
                title: Some("Google Cloud Service Health".to_string()),
                excerpt: "Multiple cloud products are experiencing networking issues in us-central1."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://azure.status.microsoft/en-us/status".to_string(),
                title: Some("Azure Status Overview - Azure Service Health | Microsoft Learn".to_string()),
                excerpt: "Note Access to this page requires authorization. You can try signing in or changing directories. Use Personalized Service Health for a more detailed overview."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://health.aws.amazon.com/health/status".to_string(),
                title: Some("AWS Health Dashboard".to_string()),
                excerpt: "Service health updates indicate elevated API error rates.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.cloud.microsoft/en-us/status".to_string(),
                title: Some("Microsoft service health status".to_string()),
                excerpt: "Investigating intermittent authentication failures.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.salesforce.com/".to_string(),
                title: Some("Salesforce Trust".to_string()),
                excerpt: "Monitoring mitigation rollout for affected tenants.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.datadoghq.com/".to_string(),
                title: Some("Datadog Status".to_string()),
                excerpt: "Partial outage under investigation.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let reply_lc = reply.to_ascii_lowercase();
    assert!(!reply_lc.contains("requires authorization"));
    assert!(!reply_lc.contains("you can try signing in"));
    assert!(!reply_lc.contains("use personalized service health"));
}

#[test]
fn web_pipeline_completion_deadline_produces_partial_low_confidence() {
    let pending = PendingSearchCompletion {
        query: "latest news".to_string(),
        query_contract: "latest news".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=latest+news".to_string(),
        started_step: 1,
        started_at_ms: 100,
        deadline_ms: 160,
        candidate_urls: vec!["https://a.example.com".to_string()],
        candidate_source_hints: vec![],
        attempted_urls: vec!["https://a.example.com".to_string()],
        blocked_urls: vec!["https://blocked.example.com".to_string()],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reason = web_pipeline_completion_reason(&pending, 200)
        .expect("deadline should produce completion reason");
    assert_eq!(reason, WebPipelineCompletionReason::DeadlineReached);

    let reply = synthesize_web_pipeline_reply(&pending, reason);
    assert!(reply.contains("Partial evidence"));
    assert!(reply.contains("Blocked sources requiring human challenge"));
    assert!(reply.contains("Run date (UTC): "));
    assert!(reply.contains("Run timestamp (UTC): "));
    assert!(reply.contains("Overall confidence: low"));
}

#[test]
fn web_pipeline_news_without_read_grounding_avoids_fabricated_story_sections() {
    let pending = PendingSearchCompletion {
        query: "today's top news headlines".to_string(),
        query_contract: "today's top news headlines".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.cnn.com/".to_string(),
            "https://www.foxnews.com/".to_string(),
            "https://www.bbc.com/news".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.cnn.com/".to_string(),
                title: Some("Breaking News, Latest News and Videos | CNN".to_string()),
                excerpt: "View the latest news and breaking news today".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.foxnews.com/".to_string(),
                title: Some("Fox News - Breaking News Updates | Latest News Headlines".to_string()),
                excerpt: "Breaking News, Latest News and Current News".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.bbc.com/news".to_string(),
                title: Some("BBC News - Breaking news".to_string()),
                excerpt: "Latest top stories".to_string(),
            },
        ],
        attempted_urls: vec![
            "https://www.cnn.com/".to_string(),
            "https://www.foxnews.com/".to_string(),
            "https://www.bbc.com/news".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    assert!(reply.contains("Synthesis unavailable"));
    assert!(!reply.contains("Story 1:"));
}

#[test]
fn web_pipeline_multi_story_query_does_not_duplicate_single_source_into_multiple_story_slots() {
    let pending = PendingSearchCompletion {
        query: "today's top news headlines".to_string(),
        query_contract: "today's top news headlines".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://www.example.com/news/main".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.example.com/news/main".to_string(),
            title: Some("Top headlines".to_string()),
            excerpt: "Top headlines include market swings and policy updates.".to_string(),
        }],
        attempted_urls: vec!["https://www.example.com/news/main".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.example.com/news/main".to_string(),
            title: Some("Top headlines".to_string()),
            excerpt: "Top headlines include market swings and policy updates.".to_string(),
        }],
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    assert!(reply.contains("Synthesis unavailable"));
    assert!(!reply.contains("Story 2:"));
    assert!(!reply.contains("Story 3:"));
}

#[test]
fn web_pipeline_restaurant_comparison_query_keeps_menu_grounding_in_multi_story_output() {
    let sources = vec![
        PendingSearchReadSummary {
            url: "https://www.carminesnyc.com/locations/upper-west-side/menus/dinner".to_string(),
            title: Some("Carmine's Upper West Side Dinner Menu".to_string()),
            excerpt:
                "Family-style Italian menu in New York, NY with spaghetti and meatballs, chicken parmigiana, lasagna and seafood pasta."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.frankrestaurant.com/menu".to_string(),
            title: Some("Frank Restaurant Dinner Menu".to_string()),
            excerpt:
                "East Village menu in New York, NY featuring pappardelle bolognese, veal parmesan, gnocchi and seasonal antipasti."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.lartusi.com/menus/dinner".to_string(),
            title: Some("L'Artusi Dinner Menu".to_string()),
            excerpt:
                "West Village menu in New York, NY with ricotta gnocchi, bucatini, roasted mushrooms and olive oil cake."
                    .to_string(),
        },
    ];
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=best+reviewed+italian+restaurants+new+york+menus"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: sources.iter().map(|source| source.url.clone()).collect(),
        candidate_source_hints: sources.clone(),
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: sources,
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);

    assert!(
        !reply.contains("Synthesis unavailable"),
        "reply was: {}",
        reply
    );
    assert!(reply.contains("Comparison:"), "reply was: {}", reply);
    assert!(
        reply.to_ascii_lowercase().contains("menu"),
        "reply was: {}",
        reply
    );
    assert_eq!(
        extract_story_titles(&reply).len(),
        3,
        "reply was: {}",
        reply
    );
}

#[test]
fn web_pipeline_headline_output_prefers_specific_articles_over_roundup_surfaces() {
    let successful_reads = vec![
        PendingSearchReadSummary {
            url: "https://www.channel3000.com/video/morning-sprint-march-6-mornings-top-news-and-weather-headlines/video_ae4a4a71-9eb5-5c14-a70a-908f6377ceaa.html".to_string(),
            title: Some(
                "Morning Sprint: March 6 morning's top news and weather headlines - Channel 3000"
                    .to_string(),
            ),
            excerpt: "Morning roundup video covering the day's top news and weather headlines."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.wmar2news.com/local/top-news-headlines-for-thursday-march-5-2026".to_string(),
            title: Some(
                "Top News Headlines for Thursday, March 5, 2026 - WMAR 2 News Baltimore"
                    .to_string(),
            ),
            excerpt: "Baltimore roundup of the day's top headlines.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7".to_string(),
            title: Some(
                "Sri Lanka takes custody of an Iranian vessel off its coast after US sank an Iranian warship - AP News"
                    .to_string(),
            ),
            excerpt:
                "AP News | source_url=https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7"
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384".to_string(),
            title: Some(
                "Mar 6: WAFCON Postponed, Uganda Evacuates 43 Students From Iran".to_string(),
            ),
            excerpt:
                "OkayAfrica | source_url=https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384"
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
            title: Some(
                "Trump tariffs: Customs and Border Protection tells judge it can't comply with refund order - CNBC".to_string(),
            ),
            excerpt:
                "CNBC | source_url=https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html"
                    .to_string(),
        },
    ];
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://news.google.com/rss?hl=en-US&gl=US&ceid=US:en".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: successful_reads
            .iter()
            .map(|source| source.url.clone())
            .collect(),
        candidate_source_hints: successful_reads.clone(),
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads,
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);

    assert!(
        !reply.contains("Synthesis unavailable"),
        "reply was: {}",
        reply
    );
    assert_eq!(
        extract_story_titles(&reply).len(),
        3,
        "reply was: {}",
        reply
    );
    let reply_lc = reply.to_ascii_lowercase();
    assert!(!reply_lc.contains("morning sprint"), "reply was: {}", reply);
    assert!(
        !reply_lc.contains("top news headlines for thursday"),
        "reply was: {}",
        reply
    );
    assert!(reply.contains("AP News"), "reply was: {}", reply);
    assert!(reply.contains("CNBC"), "reply was: {}", reply);
}

#[test]
fn web_pipeline_final_receipts_capture_same_domain_restaurant_comparison_completion() {
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Brothers Italian Cuisine",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Coach House Restaurant",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Dolce Vita Italian Bistro and Pizzeria",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                    .to_string(),
                title: Some(
                    "Brothers Italian Cuisine, Anderson - Menu, Reviews (226), Photos (25) - Restaurantji"
                        .to_string(),
                ),
                excerpt: "Italian restaurant in Anderson, SC serving pizza, pasta and subs."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                    .to_string(),
                title: Some(
                    "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                        .to_string(),
                ),
                excerpt: "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-/"
                    .to_string(),
                title: Some(
                    "Dolce Vita Italian Bistro and Pizzeria, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Italian bistro in Anderson, SC with pizza, pasta, calzones and dessert."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    let mut checks = Vec::new();
    append_final_web_completion_receipts(
        &pending,
        WebPipelineCompletionReason::ExhaustedCandidates,
        &mut checks,
    );

    assert!(checks
        .iter()
        .any(|check| { check == "web_final_story_slots_observed=3" }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_final_story_slot_floor_met=true" }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_final_story_citation_floor_met=true" }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_final_comparison_required=true" }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_final_comparison_ready=true" }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_final_single_snapshot_metric_grounding=false" }));
    assert!(checks.iter().any(|check| {
        check.contains("web_final_selected_source_url_values=https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/")
    }));
    assert!(checks.iter().any(|check| {
        check.contains("web_final_local_business_entity_matched=Brothers Italian Cuisine | Coach House Restaurant | Dolce Vita Italian Bistro and Pizzeria")
    }));
}

#[test]
fn web_pipeline_single_snapshot_completion_receipts_expose_metric_grounding() {
    let pending = PendingSearchCompletion {
        query: "What's the current price of Bitcoin?".to_string(),
        query_contract: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: None,
        url: "https://www.coindesk.com/price/bitcoin".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://crypto.news/price/bitcoin/".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.coindesk.com/price/bitcoin".to_string(),
            "https://crypto.news/price/bitcoin/".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.coindesk.com/price/bitcoin".to_string(),
                title: Some("CoinDesk Bitcoin price".to_string()),
                excerpt: "Bitcoin price right now: $68,214.99 USD as of 19:25 UTC.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://crypto.news/price/bitcoin/".to_string(),
                title: Some("Crypto.news Bitcoin price".to_string()),
                excerpt: "Current BTC quote: $68,267.00 USD.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let mut checks = Vec::new();
    append_final_web_completion_receipts(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        &mut checks,
    );

    assert!(checks
        .iter()
        .any(|check| check == "web_final_single_snapshot_metric_grounding=true"));
    assert!(checks
        .iter()
        .any(|check| check == "web_final_story_citation_floor_met=true"));
}

#[test]
fn web_pipeline_restaurant_comparison_same_domain_detail_pages_still_render_multi_story_output() {
    let sources = vec![
        PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                .to_string(),
            title: Some("Brothers Italian Cuisine".to_string()),
            excerpt:
                "Italian restaurant in Anderson, SC with stromboli, manicotti and garlic knots on the menu."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/"
                .to_string(),
            title: Some("Public Well Cafe and Pizza".to_string()),
            excerpt:
                "Italian restaurant in Anderson, SC with pizza, pasta and dinner menu specials."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/olive-garden-/".to_string(),
            title: Some("Olive Garden Italian Restaurant".to_string()),
            excerpt:
                "Italian restaurant in Anderson, SC with soup, salad, breadsticks and pasta menu classics."
                    .to_string(),
        },
    ];
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: sources.iter().map(|source| source.url.clone()).collect(),
        candidate_source_hints: sources.clone(),
        attempted_urls: vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Brothers Italian Cuisine",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Public Well Cafe and Pizza",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Olive Garden Italian Restaurant",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
        ],
        blocked_urls: vec![],
        successful_reads: sources,
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);

    assert!(
        !reply.contains("Synthesis unavailable"),
        "reply was: {}",
        reply
    );
    assert!(
        reply.contains("Brothers Italian Cuisine"),
        "reply was: {}",
        reply
    );
    assert!(
        reply.contains("Public Well Cafe and Pizza"),
        "reply was: {}",
        reply
    );
    assert!(
        reply.contains("Olive Garden Italian Restaurant"),
        "reply was: {}",
        reply
    );
    assert_eq!(
        extract_story_titles(&reply).len(),
        3,
        "reply was: {}",
        reply
    );
}

#[test]
fn web_pipeline_restaurant_comparison_prefers_one_story_per_expanded_target() {
    let sources = vec![
        PendingSearchReadSummary {
            url: "https://www.timeout.com/newyork/restaurants/roscioli-nyc".to_string(),
            title: Some("Roscioli NYC".to_string()),
            excerpt:
                "Italian restaurant in New York, NY with Roman pasta, antipasti and wine."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.yelp.com/biz/roscioli-new-york-2".to_string(),
            title: Some("Roscioli".to_string()),
            excerpt: "ROSClOLI in New York, NY with pasta, antipasti and house specialties."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.frankiesspuntino.com/menu".to_string(),
            title: Some("Frankies Spuntino Menu".to_string()),
            excerpt:
                "Italian restaurant in New York, NY serving cavatelli, meatballs and antipasti."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.viacarota.com/dinner".to_string(),
            title: Some("Via Carota Dinner".to_string()),
            excerpt:
                "Italian restaurant in New York, NY with cacio e pepe, insalata verde and seasonal vegetables."
                    .to_string(),
        },
    ];
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=best+reviewed+italian+restaurants+new+york+menus"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: sources.iter().map(|source| source.url.clone()).collect(),
        candidate_source_hints: sources.clone(),
        attempted_urls: vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Via Carota",
                    "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
                    Some("New York, NY"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Frankies Spuntino",
                    "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
                    Some("New York, NY"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Roscioli",
                    "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
                    Some("New York, NY"),
                )
                .expect("expansion query")
            ),
        ],
        blocked_urls: vec![],
        successful_reads: sources,
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let titles = extract_story_titles(&reply);
    let title_blob = titles.join(" | ").to_ascii_lowercase();

    assert_eq!(titles.len(), 3, "reply was: {}", reply);
    assert!(title_blob.contains("roscioli"), "reply was: {}", reply);
    assert!(title_blob.contains("frankies"), "reply was: {}", reply);
    assert!(title_blob.contains("via carota"), "reply was: {}", reply);
}

#[test]
fn web_pipeline_restaurant_comparison_suppresses_cookie_metadata_noise() {
    let sources = vec![
        PendingSearchReadSummary {
            url: "https://www.theinfatuation.com/new-york/reviews/misi".to_string(),
            title: Some("Misi".to_string()),
            excerpt:
                "Italian restaurant in New York, NY with handmade pasta, antipasti and vegetable dishes."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurant_Review-g60763-d25369085-Reviews-Marcellino_Restaurant-New_York_City_New_York.html".to_string(),
            title: Some("Tripadvisor".to_string()),
            excerpt:
                "Marcellino Restaurant: com','cookie':'trip-cookie-payload-12345".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurant_Review-g60763-d478005-Reviews-Pepe_Giallo-New_York_City_New_York.html".to_string(),
            title: Some("Tripadvisor".to_string()),
            excerpt: "Pepe Giallo: com','cookie':'trip-cookie-payload-67890".to_string(),
        },
    ];
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=best+reviewed+italian+restaurants+new+york+menus"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: sources.iter().map(|source| source.url.clone()).collect(),
        candidate_source_hints: sources.clone(),
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: sources,
        min_sources: 3,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    let reply_lc = reply.to_ascii_lowercase();

    assert!(reply.contains("Pepe Giallo"), "reply was: {}", reply);
    assert!(
        reply.contains("Marcellino Restaurant"),
        "reply was: {}",
        reply
    );
    assert!(
        !reply_lc.contains("cookie':'"),
        "reply leaked cookie metadata noise: {}",
        reply
    );
    assert!(
        !reply_lc.contains("trip-cookie-payload"),
        "reply leaked cookie metadata noise: {}",
        reply
    );
}

#[test]
fn web_pipeline_local_business_target_selection_prefers_primary_surface_over_review_aggregator() {
    let selected = selected_local_business_target_sources(
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.",
        &["Carbone".to_string()],
        &[
            PendingSearchReadSummary {
                url: "https://www.tripadvisor.com/Restaurant_Review-g60763-d1234567-Reviews-Carbone-New_York_City_New_York.html".to_string(),
                title: Some("Carbone - Menu, Prices & Restaurant Reviews - Tripadvisor".to_string()),
                excerpt: "Carbone in New York, NY with menu, photos and traveler reviews."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://carbonenewyork.com/menu".to_string(),
                title: Some("Carbone New York Menu".to_string()),
                excerpt: "Italian restaurant menu in New York, NY with spicy rigatoni vodka, veal parmesan and Caesar alla ZZ."
                    .to_string(),
            },
        ],
        Some("New York, NY"),
        1,
    );

    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].url, "https://carbonenewyork.com/menu");
}

#[test]
fn web_pipeline_append_success_skips_terminal_error_pages() {
    let mut pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=best+reviewed+italian+restaurants+new+york+menus"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc"
            .to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc"
                .to_string(),
            title: Some("404 Not Found | Eater NY".to_string()),
            excerpt: "Sorry, the page you were looking for could not be found.".to_string(),
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
        backend: "edge:playwright:http".to_string(),
        query: None,
        url: Some(
            "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc".to_string(),
        ),
        sources: vec![WebSource {
            source_id: "eater-404".to_string(),
            rank: Some(1),
            url: "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc".to_string(),
            title: Some("404 Not Found | Eater NY".to_string()),
            snippet: Some("Sorry, the page you were looking for could not be found.".to_string()),
            domain: Some("ny.eater.com".to_string()),
        }],
        source_observations: vec![],
        documents: vec![WebDocument {
            source_id: "eater-404".to_string(),
            url: "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc".to_string(),
            title: Some("404 Not Found | Eater NY".to_string()),
            content_text: "404 Not Found. Sorry, the page you were looking for could not be found."
                .to_string(),
            content_hash: "deadbeef".to_string(),
            quote_spans: vec![],
        }],
        provider_candidates: vec![],
        retrieval_contract: None,
    };

    append_pending_web_success_from_bundle(
        &mut pending,
        &bundle,
        "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc",
    );

    assert!(
        pending.successful_reads.is_empty(),
        "terminal error pages should not count as successful reads: {:?}",
        pending.successful_reads
    );
}

#[test]
fn web_pipeline_headline_reply_excludes_blocked_and_internal_probe_urls_from_citations() {
    let pending = PendingSearchCompletion {
        query: "Tell me today's top news headlines.".to_string(),
        query_contract: "Tell me today's top news headlines.".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=today+top+news+headlines".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec!["https://www.npr.org/sections/news/".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.npr.org/sections/news/".to_string(),
            title: Some("News : U.S. and World News Headlines : NPR".to_string()),
            excerpt: "Coverage of breaking stories, national and world news.".to_string(),
        }],
        attempted_urls: vec![
            "https://www.npr.org/sections/news/".to_string(),
            "ioi://quality-recovery/probe".to_string(),
        ],
        blocked_urls: vec!["https://www.npr.org/sections/news/".to_string()],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::ExhaustedCandidates);
    assert!(reply.contains("Synthesis unavailable"));
    assert!(!reply.contains("What happened:"));
    assert!(!reply.contains("ioi://quality-recovery/probe"));
    assert!(!reply.contains(
        "News : U.S. and World News Headlines : NPR | https://www.npr.org/sections/news/"
    ));
    assert!(reply
        .contains("Blocked sources requiring human challenge: https://www.npr.org/sections/news/"));
}

#[test]
fn web_pipeline_single_fact_query_prefers_direct_answer_layout() {
    let pending = PendingSearchCompletion {
        query: "Who is the latest OpenAI CEO?".to_string(),
        query_contract: "Who is the latest OpenAI CEO?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=latest+OpenAI+CEO".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://openai.com/".to_string(),
            "https://en.wikipedia.org/wiki/OpenAI".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://openai.com/".to_string(),
            title: Some("OpenAI leadership".to_string()),
            excerpt: "OpenAI is led by CEO Sam Altman.".to_string(),
        }],
        attempted_urls: vec!["https://openai.com/".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://openai.com/".to_string(),
            title: Some("OpenAI leadership".to_string()),
            excerpt: "OpenAI is led by CEO Sam Altman.".to_string(),
        }],
        min_sources: 1,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("What happened:"));
    assert!(!reply.contains("Story 1:"));
    assert!(!reply.contains("Answer:"));
    assert!(!reply.contains("Context:"));
}

#[test]
fn web_pipeline_reply_enforces_three_story_structure_with_citations_and_timestamps() {
    let pending = PendingSearchCompletion {
        query: "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents (major status pages), what changed in last hour, user impact, workaround, ETA confidence, 2 citations each."
            .to_string(),
        query_contract: "As of now (UTC), top 3 active U.S.-impacting cloud/SaaS incidents (major status pages), what changed in last hour, user impact, workaround, ETA confidence, 2 citations each."
            .to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=cloud+saas+status+incidents".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://status.example.com/incidents/a".to_string(),
            "https://status.example.com/incidents/b".to_string(),
            "https://status.example.com/incidents/c".to_string(),
            "https://status.example.com/incidents/d".to_string(),
            "https://status.example.com/incidents/e".to_string(),
            "https://status.example.com/incidents/f".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.example.com/incidents/a".to_string(),
                title: Some("Major provider outage impacts API authentication".to_string()),
                excerpt: "Investigating elevated auth errors for U.S. users; mitigation in progress."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.example.com/incidents/b".to_string(),
                title: Some("Dashboard degradation in North America region".to_string()),
                excerpt: "Users may see slow dashboard loads; workaround includes retrying in alternate region.".to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.example.com/incidents/c".to_string(),
                title: Some("Storage control plane incident under active monitoring".to_string()),
                excerpt: "Provider identified root cause and expects next update within 30 minutes."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://status.example.com/incidents/d".to_string(),
                title: Some("Service health: intermittent request timeout".to_string()),
                excerpt: "Mitigation rolled out to reduce elevated latency for U.S. tenants.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 2,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Story 1:"));
    assert!(reply.contains("Story 2:"));
    assert!(reply.contains("Story 3:"));
    assert_eq!(reply.matches("What happened:").count(), 3);
    assert_eq!(reply.matches("What changed in the last hour:").count(), 3);
    assert_eq!(reply.matches("User impact:").count(), 3);
    assert_eq!(reply.matches("Workaround:").count(), 3);
    assert_eq!(reply.matches("ETA confidence:").count(), 3);
    assert_eq!(reply.matches("Citations:").count(), 3);
    assert!(reply.contains("T") && reply.contains("Z"));
    let urls = extract_urls(&reply);
    assert!(
        urls.len() >= 3,
        "expected >= 3 distinct urls, got {}",
        urls.len()
    );
}

#[test]
fn web_pipeline_renders_single_snapshot_for_time_sensitive_public_fact_queries() {
    let pending = PendingSearchCompletion {
        query: "What's the weather right now in Anderson, SC?".to_string(),
        query_contract: "What's the weather right now in Anderson, SC?".to_string(),
        retrieval_contract: None,
        url: "https://duckduckgo.com/?q=anderson+sc+weather+right+now".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://forecast.weather.gov/MapClick.php?textField1=34.50&textField2=-82.65"
                .to_string(),
            "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
        ],
        candidate_source_hints: vec![
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://forecast.weather.gov/MapClick.php?textField1=34.50&textField2=-82.65"
                    .to_string(),
                title: Some("Anderson SC Forecast Office Update".to_string()),
                excerpt: "Current conditions: cloudy skies, temperature near 61 F, calm wind, humidity near 48 percent."
                    .to_string(),
            },
            crate::agentic::desktop::types::PendingSearchReadSummary {
                url: "https://www.accuweather.com/en/us/anderson/29621/current-weather/331327".to_string(),
                title: Some("Anderson, SC Current Weather".to_string()),
                excerpt: "Feels like low 60s with overcast conditions and light wind.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![],
        min_sources: 1,
    };

    let reply =
        synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert!(reply.contains("Right now"));
    assert!(reply.contains("Citations:"));
    assert!(reply.contains("Run timestamp (UTC):"));
    assert!(!reply.contains("Story 2:"));
    assert!(!reply.contains("Story 3:"));
}

#[test]
fn web_pipeline_user_renderer_has_no_env_gated_weather_baseline_bypass() {
    let renderer_source = include_str!("../../support/synthesis/draft/renderers/mod.rs");

    assert!(
        !renderer_source.contains("IOI_WEATHER_BASELINE_RENDER"),
        "env-gated query-specific weather baseline bypass must not exist in user synthesis renderer"
    );
    assert!(
        !renderer_source.contains("query_matches_weather_baseline_contract"),
        "query-specific weather baseline contract matching must not exist in user synthesis renderer"
    );
}
