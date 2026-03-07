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
