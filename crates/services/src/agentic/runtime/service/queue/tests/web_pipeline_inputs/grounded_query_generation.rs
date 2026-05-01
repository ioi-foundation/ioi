use super::*;

include!("grounded_query_generation/search_query.rs");

include!("grounded_query_generation/query_contract.rs");

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

include!("grounded_query_generation/local_business.rs");

include!("grounded_query_generation/probe_query.rs");
