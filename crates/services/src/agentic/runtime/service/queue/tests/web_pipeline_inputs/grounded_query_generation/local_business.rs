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
fn web_pipeline_local_business_entity_anchor_derives_unquoted_cuisine_token() {
    let search_query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";

    assert_eq!(
        local_business_search_entity_anchor_tokens(search_query, Some("Anderson, SC")),
        vec!["italian".to_string()]
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
