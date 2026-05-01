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
