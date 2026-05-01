use super::*;

fn restaurant_query_contract() -> String {
    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
        .to_string()
}

#[test]
fn retains_discovery_seed_when_direct_detail_candidates_do_not_cover_distinct_entities() {
    let query_contract = restaurant_query_contract();
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(&query_contract, None)
            .expect("retrieval contract");
    let source_hints = vec![
        PendingSearchReadSummary {
            url: "https://www.yelp.com/biz/dolce-vita-italian-bistro-and-pizzeria-anderson"
                .to_string(),
            title: Some(
                "Dolce Vita Italian Bistro and Pizzeria - Anderson, SC - Yelp".to_string(),
            ),
            excerpt: "Italian restaurant in Anderson, SC with pasta, pizza, and baked dishes."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurant_Review-g30090-d15074041-Reviews-DolceVita_Italian_Bistro_Pizzeria-Anderson_South_Carolina.html".to_string(),
            title: Some(
                "DolceVita Italian Bistro & Pizzeria - Tripadvisor".to_string(),
            ),
            excerpt:
                "Italian restaurant in Anderson, South Carolina serving pizza and pasta."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://theredtomatorestaurant.com/".to_string(),
            title: Some("The Red Tomato and Wine Bar | Anderson, SC".to_string()),
            excerpt: "Italian dining in Anderson, SC with wine, pasta, and entrees."
                .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.yelp.com/search?cflt=italian&find_loc=Anderson,+SC".to_string(),
            title: Some(
                "Top 10 Best Italian Restaurants Near Anderson, South Carolina - Yelp"
                    .to_string(),
            ),
            excerpt:
                "Best Italian in Anderson, SC: Dolce Vita Italian Bistro, The Red Tomato and Brothers Italian Cuisine."
                    .to_string(),
        },
    ];
    let candidate_urls = source_hints
        .iter()
        .map(|hint| hint.url.clone())
        .collect::<Vec<_>>();

    let output = collect_projection_candidate_urls_with_contract_and_locality_hint(
        Some(&retrieval_contract),
        &query_contract,
        3,
        &[],
        &source_hints,
        3,
        3,
        &BTreeSet::new(),
        Some("Anderson, SC"),
    );

    assert!(
        output.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://www.yelp.com/search?cflt=italian&find_loc=Anderson,+SC"
            )
        }),
        "{output:?}"
    );
    assert!(output.len() <= candidate_urls.len());
}
