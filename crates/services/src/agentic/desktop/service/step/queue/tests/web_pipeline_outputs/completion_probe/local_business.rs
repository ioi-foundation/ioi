#[test]
fn web_pipeline_local_business_comparison_defers_completion_until_distinct_entities_are_matched() {
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
        candidate_urls: vec!["https://www.viacarota.com/dinner".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.viacarota.com/dinner".to_string(),
            title: Some("Via Carota Dinner".to_string()),
            excerpt: "Italian restaurant in New York, NY serving cacio e pepe and seasonal plates."
                .to_string(),
        }],
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
                    "Frankies (457) Spuntino",
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
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.timeout.com/newyork/restaurants/roscioli-nyc".to_string(),
                title: Some("Roscioli NYC".to_string()),
                excerpt:
                    "Italian restaurant in New York, NY with Roman pasta, wine and antipasti."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.yelp.com/biz/roscioli-new-york-2".to_string(),
                title: Some("Roscioli".to_string()),
                excerpt:
                    "ROSClOLI in New York, NY with pasta, antipasti and house specialties."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    assert!(query_requires_local_business_entity_diversity(
        &pending.query_contract
    ));
    assert_eq!(
        local_business_target_names_from_attempted_urls(
            &pending.attempted_urls,
            Some("New York, NY")
        ),
        vec![
            "Via Carota".to_string(),
            "Frankies Spuntino".to_string(),
            "Roscioli".to_string()
        ]
    );
    assert_eq!(
        matched_local_business_target_names(
            &[
                "Via Carota".to_string(),
                "Frankies Spuntino".to_string(),
                "Roscioli".to_string()
            ],
            &pending.successful_reads,
            Some("New York, NY")
        ),
        vec!["Roscioli".to_string()]
    );

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "distinct-entity floor gap should keep the local-business comparison pipeline active; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_local_business_comparison_defers_completion_until_targets_are_discovered() {
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
        candidate_urls: vec![
            "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc"
                .to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc"
                .to_string(),
            title: Some("Best Italian Restaurants in NYC".to_string()),
            excerpt:
                "Menus, reviews and ratings for Italian restaurants in New York, NY."
                    .to_string(),
        }],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.eater.com/nyc/italian-restaurant-reviews".to_string(),
                title: Some("The Best Italian Restaurants in NYC".to_string()),
                excerpt:
                    "Restaurant reviews and dining guide for the best Italian restaurants in New York, NY."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc"
                    .to_string(),
                title: Some("Best Italian Restaurants in NYC".to_string()),
                excerpt:
                    "Menus, reviews and ratings for Italian restaurants in New York, NY."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nytimes.com/section/dining/italian-restaurants-nyc"
                    .to_string(),
                title: Some("Italian Restaurants NYC".to_string()),
                excerpt:
                    "Dining coverage of Italian restaurants in New York, NY with review context."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    assert!(query_requires_local_business_entity_diversity(
        &pending.query_contract
    ));
    assert_eq!(
        local_business_target_names_from_attempted_urls(
            &pending.attempted_urls,
            Some("New York, NY")
        ),
        Vec::<String>::new()
    );

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000);
    assert!(
        reason.is_none(),
        "missing target discovery should keep the local-business comparison pipeline active; got {:?}",
        reason
    );
}

#[test]
fn web_pipeline_local_business_comparison_completes_with_same_domain_distinct_target_sources() {
    let pending = PendingSearchCompletion {
        query: "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
            .to_string(),
        query_contract:
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
                .to_string(),
        retrieval_contract: None,
        url: "https://www.bing.com/search?q=italian+restaurants+anderson+sc".to_string(),
        started_step: 1,
        started_at_ms: 1_771_465_364_000,
        deadline_ms: 1_771_465_424_000,
        candidate_urls: vec![
            "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/".to_string(),
            "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/"
                .to_string(),
            "https://www.restaurantji.com/sc/anderson/the-common-house-/".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
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
                    "Dolce Vita Italian Bistro and Pizzeria",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "The Common House",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/"
                    .to_string(),
                title: Some(
                    "Public Well Cafe and Pizza, Anderson - Menu, Reviews (205), Photos (34) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Italian restaurant in Anderson, SC with pizza, pasta, sandwiches and 205 reviews."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/"
                    .to_string(),
                title: Some(
                    "Dolce Vita Italian Bistro and Pizzeria, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Italian restaurant in Anderson, SC with pasta, pizza, menu highlights and 278 reviews."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/the-common-house-/".to_string(),
                title: Some(
                    "The Common House, Anderson - Menu, Reviews (231), Photos (41) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Restaurant in Anderson, SC with dinner menu specials, cocktails and 231 reviews."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    let reason = web_pipeline_completion_reason(&pending, 1_771_465_380_000)
        .expect("same-domain distinct target sources should allow completion");
    assert_eq!(reason, WebPipelineCompletionReason::MinSourcesReached);
}
