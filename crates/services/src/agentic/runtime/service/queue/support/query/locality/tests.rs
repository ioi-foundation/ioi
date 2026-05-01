use super::*;

#[test]
fn category_titles_are_rejected_as_local_business_targets() {
    let source = PendingSearchReadSummary {
        url: "https://www.restaurantji.com/sc/anderson/vegetarian/".to_string(),
        title: Some("Best Vegetarian Restaurants".to_string()),
        excerpt: "THE 10 BEST Italian Restaurants in Anderson, SC with reviews, ratings and menus."
            .to_string(),
    };

    assert!(local_business_collection_surface_candidate(
        Some("Anderson, SC"),
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    ));
    assert_eq!(
        local_business_target_name_from_source(&source, Some("Anderson, SC")),
        None
    );
}

#[test]
fn restaurant_titles_remain_valid_local_business_targets() {
    let source = PendingSearchReadSummary {
        url: "https://www.restaurantji.com/sc/anderson/olive-garden-/".to_string(),
        title: Some("Olive Garden Italian Restaurant".to_string()),
        excerpt: "Italian restaurant in Anderson, SC with pasta, soup and breadsticks.".to_string(),
    };

    assert!(!local_business_collection_surface_candidate(
        Some("Anderson, SC"),
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    ));
    assert_eq!(
        local_business_target_name_from_source(&source, Some("Anderson, SC")).as_deref(),
        Some("Olive Garden Italian Restaurant")
    );
}

#[test]
fn typed_business_suffix_titles_remain_valid_local_business_targets() {
    let source = PendingSearchReadSummary {
        url: "https://www.frankrestaurant.com/menu".to_string(),
        title: Some("Frank Restaurant Dinner Menu".to_string()),
        excerpt:
            "East Village menu in New York, NY featuring pappardelle bolognese, veal parmesan, gnocchi and seasonal antipasti."
                .to_string(),
    };

    assert_eq!(
        local_business_target_name_from_source(&source, Some("New York, NY")).as_deref(),
        Some("Frank Restaurant")
    );
}

#[test]
fn typed_business_suffix_slugs_remain_valid_local_business_targets() {
    let source = PendingSearchReadSummary {
        url: "https://www.tripadvisor.com/Restaurant_Review-g60763-d25369085-Reviews-Marcellino_Restaurant-New_York_City_New_York.html".to_string(),
        title: Some("Tripadvisor".to_string()),
        excerpt:
            "Marcellino Restaurant: com','cookie':'trip-cookie-payload-12345".to_string(),
    };

    assert_eq!(
        local_business_target_name_from_source(&source, Some("New York, NY")).as_deref(),
        Some("Marcellino Restaurant")
    );
}

#[test]
fn locality_listing_identity_is_not_treated_as_business_entity() {
    let source = PendingSearchReadSummary {
        url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
            .to_string(),
        title: Some("Restaurants Anderson South Carolina".to_string()),
        excerpt: "Browse Anderson dining results and traveler review rankings.".to_string(),
    };

    assert!(!local_business_entity_name_allowed(
        "Restaurants Anderson South Carolina",
        Some("Anderson, SC")
    ));
    assert_eq!(
        local_business_target_name_from_source(&source, Some("Anderson, SC")),
        None
    );
    assert!(!source_matches_local_business_target_name(
        "Restaurants Anderson South Carolina",
        Some("Anderson, SC"),
        "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/",
        "Brothers Italian Cuisine",
        "Italian restaurant in Anderson, SC with stromboli and manicotti."
    ));
}

#[test]
fn locality_category_title_with_host_suffix_is_not_treated_as_business_entity() {
    let source = PendingSearchReadSummary {
        url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
            .to_string(),
        title: Some("Italian Restaurants in Anderson - Tripadvisor".to_string()),
        excerpt:
            "Tripadvisor traveller reviews for Italian restaurants in Anderson, South Carolina."
                .to_string(),
    };

    assert_eq!(
        local_business_target_name_from_source(&source, Some("Anderson, SC")),
        None
    );
}

#[test]
fn local_business_discovery_query_contract_trims_post_scope_comparison_tail() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let discovery = local_business_discovery_query_contract(query, Some("Anderson, SC"));

    assert_eq!(
        discovery,
        "Find the three best-reviewed Italian restaurants in Anderson, SC"
    );
}

#[test]
fn explicit_query_scope_hint_trims_post_scope_comparison_tail() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";

    assert_eq!(
        explicit_query_scope_hint(query).as_deref(),
        Some("Anderson, SC")
    );
}

#[test]
fn local_business_entity_discovery_query_contract_uses_entity_class_not_comparison_axis() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let discovery = local_business_entity_discovery_query_contract(query, Some("Anderson, SC"));
    let normalized = discovery.to_ascii_lowercase();

    assert!(
        normalized.contains("italian restaurants in anderson")
            || normalized.contains("restaurants in anderson"),
        "query={discovery}"
    );
    assert!(!normalized.contains("compare"), "query={discovery}");
    assert!(!normalized.contains("menus"), "query={discovery}");
}

#[test]
fn local_business_entity_discovery_query_contract_recovers_entity_class_from_inflated_search_query()
{
    let query =
        "italian restaurants menus in Anderson, SC \"italian restaurants menus\" \"Anderson, SC\"";
    let discovery = local_business_entity_discovery_query_contract(query, Some("Anderson, SC"));
    let normalized = discovery.to_ascii_lowercase();

    assert!(
        normalized.contains("italian restaurants in anderson")
            || normalized.contains("restaurants in anderson"),
        "query={discovery}"
    );
    assert!(!normalized.contains("menus"), "query={discovery}");
}

#[test]
fn merged_targets_backfill_from_detail_sources_when_attempted_target_only_has_search_hub() {
    let attempted_urls = vec![
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
                "Olive Garden",
                "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                Some("Anderson, SC"),
            )
            .expect("expansion query")
        ),
    ];
    let sources = vec![
        PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/".to_string(),
            title: Some("Brothers Italian Cuisine".to_string()),
            excerpt: "Italian restaurant in Anderson, SC with stromboli and manicotti.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/"
                .to_string(),
            title: Some("Public Well Cafe and Pizza".to_string()),
            excerpt: "Italian restaurant in Anderson, SC with pizza and pasta.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/".to_string(),
            title: Some("Coach House Restaurant".to_string()),
            excerpt: "Anderson, SC restaurant with ravioli, lasagna and dinner plates.".to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.yelp.com/search?cflt=italian&find_loc=Anderson,%20sc".to_string(),
            title: Some("Best Italian in Anderson, SC".to_string()),
            excerpt: "Olive Garden, Dolce Vita Italian Bistro and Coach House Restaurant."
                .to_string(),
        },
    ];

    let targets =
        merged_local_business_target_names(&attempted_urls, &sources, Some("Anderson, SC"), 3);

    assert_eq!(
        targets,
        vec![
            "Brothers Italian Cuisine".to_string(),
            "Public Well Cafe and Pizza".to_string(),
            "Coach House Restaurant".to_string(),
        ]
    );
}

#[test]
fn generic_menu_title_detail_page_falls_back_to_url_target_identity() {
    let source = PendingSearchReadSummary {
        url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/".to_string(),
        title: Some("Menu".to_string()),
        excerpt: "View the menu, hours, phone number, address and map for Coach House Restaurant."
            .to_string(),
    };

    assert!(local_business_menu_surface_url(&source.url));
    assert!(
        local_business_target_name_from_source(&source, Some("Anderson, SC"))
            .is_some_and(|value| value.eq_ignore_ascii_case("Coach House Restaurant"))
    );
    assert!(
        local_business_detail_display_name(&source, Some("Anderson, SC"))
            .is_some_and(|value| value.eq_ignore_ascii_case("Coach House Restaurant"))
    );
    assert!(local_business_final_detail_source_allowed(
        &source,
        Some("Anderson, SC")
    ));
    assert!(source_matches_local_business_target_name(
        "Coach House Restaurant",
        Some("Anderson, SC"),
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    ));
    assert!(query_requires_local_business_menu_surface(
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
        None,
        Some("Anderson, SC"),
    ));

    let selected = selected_local_business_target_sources(
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
        &["Coach House Restaurant".to_string()],
        &[
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                    .to_string(),
                title: Some(
                    "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                        .to_string(),
                ),
                excerpt:
                    "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                        .to_string(),
            },
            source.clone(),
        ],
        Some("Anderson, SC"),
        1,
    );
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].url, source.url);
}
