use anyhow::anyhow;
use ioi_types::app::agentic::{WebRetrievalContract, WebSource};

use super::anchor_policy::{
    filter_provider_sources_by_query_anchors, provider_sources_match_query_anchors,
};
use super::constants::EDGE_WEB_SEARCH_TOTAL_BUDGET_MS;
use super::contract::contract_requires_geo_scoped_entity_expansion;
use super::parsers::{
    parse_bing_news_sources_from_rss, parse_bing_sources_from_html, parse_brave_sources_from_html,
    parse_ddg_sources_from_html, parse_generic_page_source_from_html,
    parse_google_news_sources_from_rss, parse_json_ld_item_list_sources_from_html,
    parse_same_host_child_collection_sources_from_html,
};
use super::readability::{
    build_document_text_and_spans, extract_non_html_read_blocks, extract_read_blocks,
    extract_read_blocks_for_url,
};
use super::search::{
    aggregated_sources_meet_pre_read_floor, provider_candidate_is_usable,
    provider_candidate_selection_key, provider_descriptor_is_admissible,
    provider_probe_priority_key, search_budget_exhausted, search_provider_registry,
    search_provider_requirements_from_contract, should_stop_provider_aggregation,
    SearchProviderCandidateSelectionInput,
};
use super::transport::{
    detect_human_challenge, fetch_html_http_fallback_browser_ua, retrieve_html_with_fallback,
    transport_error_is_timeout_or_hang,
};
use super::types::{SearchProviderRequirements, SearchProviderStage};
use super::urls::{
    build_bing_search_rss_url, build_bing_serp_url, build_brave_serp_url, build_ddg_serp_url,
    build_google_news_serp_url, build_google_news_top_stories_rss_url, build_google_serp_url,
    build_restaurantji_locality_root_url, build_weather_gov_locality_lookup_url,
    build_wttr_locality_current_conditions_url, normalize_google_search_href,
    normalize_search_href,
};
use super::util::{domain_for_url, now_ms, source_id_for_url};

fn test_source(url: &str, title: &str, snippet: &str) -> WebSource {
    WebSource {
        source_id: source_id_for_url(url),
        rank: Some(1),
        url: url.to_string(),
        title: Some(title.to_string()),
        snippet: Some(snippet.to_string()),
        domain: domain_for_url(url),
    }
}

fn base_contract() -> WebRetrievalContract {
    WebRetrievalContract {
        contract_version: "test.v1".to_string(),
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: false,
        runtime_locality_required: false,
        source_independence_min: 1,
        citation_count_min: 1,
        structured_record_preferred: false,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: false,
        discovery_surface_required: true,
        entity_diversity_required: false,
        scalar_measure_required: false,
        browser_fallback_allowed: true,
    }
}

fn headline_contract() -> WebRetrievalContract {
    let mut contract = base_contract();
    contract.entity_cardinality_min = 3;
    contract.currentness_required = true;
    contract.source_independence_min = 3;
    contract.citation_count_min = 2;
    contract.ordered_collection_preferred = true;
    contract
}

fn price_snapshot_contract() -> WebRetrievalContract {
    let mut contract = base_contract();
    contract.currentness_required = true;
    contract.discovery_surface_required = false;
    contract.structured_record_preferred = true;
    contract.scalar_measure_required = true;
    contract
}

fn weather_snapshot_contract() -> WebRetrievalContract {
    let mut contract = price_snapshot_contract();
    contract.runtime_locality_required = true;
    contract.geo_scoped_detail_required = true;
    contract
}

fn misclassified_weather_snapshot_contract() -> WebRetrievalContract {
    let mut contract = weather_snapshot_contract();
    contract.discovery_surface_required = true;
    contract
}

fn locality_comparison_contract() -> WebRetrievalContract {
    let mut contract = base_contract();
    contract.entity_cardinality_min = 3;
    contract.comparison_required = true;
    contract.runtime_locality_required = true;
    contract.source_independence_min = 3;
    contract.link_collection_preferred = true;
    contract.canonical_link_out_preferred = true;
    contract.geo_scoped_detail_required = true;
    contract.entity_diversity_required = true;
    contract
}

fn misclassified_headline_contract() -> WebRetrievalContract {
    let mut contract = headline_contract();
    contract.link_collection_preferred = true;
    contract.canonical_link_out_preferred = true;
    contract.entity_diversity_required = true;
    contract
}

#[test]
fn ddg_serp_url_encodes_query() {
    let url = build_ddg_serp_url("internet of intelligence");
    assert!(url.starts_with("https://duckduckgo.com/"));
    assert!(url.contains("q=internet+of+intelligence"));
}

#[test]
fn provider_specific_search_urls_encode_query() {
    let google = build_google_serp_url("internet of intelligence");
    assert!(google.starts_with("https://www.google.com/search"));
    assert!(google.contains("q=internet+of+intelligence"));

    let google_news = build_google_news_serp_url("internet of intelligence");
    assert!(google_news.starts_with("https://www.google.com/search"));
    assert!(google_news.contains("q=internet+of+intelligence"));
    assert!(google_news.contains("tbm=nws"));
    assert!(google_news.contains("hl=en-US"));
    assert!(google_news.contains("gl=US"));

    let bing = build_bing_serp_url("internet of intelligence");
    assert!(bing.starts_with("https://www.bing.com/search"));
    assert!(bing.contains("q=internet+of+intelligence"));

    let bing_rss = build_bing_search_rss_url("internet of intelligence");
    assert!(bing_rss.starts_with("https://www.bing.com/search"));
    assert!(bing_rss.contains("q=internet+of+intelligence"));
    assert!(bing_rss.contains("format=rss"));

    let brave = build_brave_serp_url("internet of intelligence");
    assert!(brave.starts_with("https://search.brave.com/search"));
    assert!(brave.contains("q=internet+of+intelligence"));

    let wttr = build_wttr_locality_current_conditions_url("Anderson, SC");
    assert!(wttr.starts_with("https://wttr.in/"));
    assert!(wttr.contains("format="));

    let weather_gov = build_weather_gov_locality_lookup_url("Anderson, SC");
    assert!(weather_gov.starts_with("https://forecast.weather.gov/zipcity.php"));
    assert!(weather_gov.contains("inputstring=Anderson%2C+SC"));

    let restaurantji =
        build_restaurantji_locality_root_url("Anderson, SC").expect("restaurantji locality url");
    assert_eq!(restaurantji, "https://www.restaurantji.com/sc/anderson/");
}

#[test]
fn search_provider_requirements_prefer_ordered_collection_for_headlines() {
    let contract = headline_contract();
    let requirements = search_provider_requirements_from_contract(&contract, None);
    assert_eq!(
        requirements,
        SearchProviderRequirements {
            freshness_bias: true,
            ordered_collection_preferred: true,
            structured_record_preferred: false,
            link_collection_preferred: false,
            canonical_link_out_preferred: false,
            currentness_required: true,
            locality_scope_required: false,
            discovery_surface_required: true,
            geo_scoped_detail_required: false,
            browser_fallback_allowed: true,
        }
    );
}

fn descriptor_for(stage: SearchProviderStage) -> super::search::SearchProviderDescriptor {
    search_provider_registry()
        .iter()
        .copied()
        .find(|descriptor| descriptor.stage == stage)
        .expect("provider descriptor present in registry")
}

#[test]
fn discovery_backed_selection_prefers_ordered_collection_candidates_when_required() {
    let contract = headline_contract();
    let requirements = search_provider_requirements_from_contract(&contract, None);
    let google_news = descriptor_for(SearchProviderStage::GoogleNewsTopStoriesRss);
    let brave = descriptor_for(SearchProviderStage::BraveHttp);
    let bing = descriptor_for(SearchProviderStage::BingHttp);

    let mut candidates = [
        SearchProviderCandidateSelectionInput {
            descriptor: &brave,
            source_count: 6,
            challenge_present: false,
        },
        SearchProviderCandidateSelectionInput {
            descriptor: &google_news,
            source_count: 2,
            challenge_present: false,
        },
        SearchProviderCandidateSelectionInput {
            descriptor: &bing,
            source_count: 4,
            challenge_present: false,
        },
    ];
    candidates.sort_by_key(|candidate| provider_candidate_selection_key(&requirements, *candidate));

    assert_eq!(
        candidates
            .first()
            .map(|candidate| candidate.descriptor.stage),
        Some(SearchProviderStage::GoogleNewsTopStoriesRss)
    );
}

#[test]
fn discovery_backed_selection_prefers_queryable_index_candidates_for_snapshot_queries() {
    let contract = price_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, None);
    let google_news = descriptor_for(SearchProviderStage::GoogleNewsRss);
    let brave = descriptor_for(SearchProviderStage::BraveHttp);
    let bing = descriptor_for(SearchProviderStage::BingHttp);

    let mut candidates = [
        SearchProviderCandidateSelectionInput {
            descriptor: &google_news,
            source_count: 8,
            challenge_present: false,
        },
        SearchProviderCandidateSelectionInput {
            descriptor: &brave,
            source_count: 2,
            challenge_present: false,
        },
        SearchProviderCandidateSelectionInput {
            descriptor: &bing,
            source_count: 3,
            challenge_present: false,
        },
    ];
    candidates.sort_by_key(|candidate| provider_candidate_selection_key(&requirements, *candidate));

    assert_eq!(
        candidates
            .first()
            .map(|candidate| candidate.descriptor.stage),
        Some(SearchProviderStage::BingHttp)
    );
}

#[test]
fn ordered_collection_aggregation_continues_until_pre_read_floor_is_met() {
    let mut contract = headline_contract();
    contract.entity_cardinality_min = 5;
    contract.source_independence_min = 5;

    let first_batch = vec![
        test_source(
            "https://alpha.example.com/news/world/story-one",
            "Story One",
            "alpha source",
        ),
        test_source(
            "https://beta.example.com/news/world/story-two",
            "Story Two",
            "beta source",
        ),
        test_source(
            "https://gamma.example.com/news/world/story-three",
            "Story Three",
            "gamma source",
        ),
        test_source(
            "https://delta.example.com/news/world/story-four",
            "Story Four",
            "delta source",
        ),
        test_source(
            "https://alpha.example.com/news/world/story-five",
            "Story Five",
            "alpha duplicate domain",
        ),
    ];
    assert!(!aggregated_sources_meet_pre_read_floor(
        &contract,
        "Tell me today's top news headlines.",
        None,
        10,
        &first_batch,
    ));

    let mut second_batch = first_batch;
    second_batch.push(test_source(
        "https://epsilon.example.com/news/world/story-six",
        "Story Six",
        "epsilon source",
    ));
    assert!(aggregated_sources_meet_pre_read_floor(
        &contract,
        "Tell me today's top news headlines.",
        None,
        10,
        &second_batch,
    ));
}

#[test]
fn direct_snapshot_aggregation_stops_after_structured_detail_provider_meets_floor() {
    let contract = weather_snapshot_contract();
    let weather_gov = descriptor_for(SearchProviderStage::WeatherGovLocalityDetail);
    let sources = vec![test_source(
        "https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC&site=GSP&textField1=34.5186&textField2=-82.6458&e=0",
        "Anderson, SC current conditions",
        "Current conditions as of 10:35 AM: temperature 62F, humidity 42%, wind 4 mph.",
    )];

    assert!(should_stop_provider_aggregation(
        &contract,
        "What's the weather like right now in Anderson, SC?",
        Some("Anderson, SC"),
        10,
        10,
        &sources,
        Some(&weather_gov),
        false,
    ));
}

#[test]
fn direct_snapshot_aggregation_does_not_stop_on_queryable_index_floor_alone() {
    let contract = weather_snapshot_contract();
    let brave = descriptor_for(SearchProviderStage::BraveHttp);
    let sources = vec![test_source(
        "https://www.wunderground.com/weather/us/sc/anderson",
        "Anderson, SC Weather Conditions",
        "Current conditions as of 10:35 AM: temperature 62F, humidity 42%, wind 4 mph.",
    )];

    assert!(!should_stop_provider_aggregation(
        &contract,
        "What's the weather like right now in Anderson, SC?",
        Some("Anderson, SC"),
        10,
        10,
        &sources,
        Some(&brave),
        false,
    ));
}

#[test]
fn probe_priority_prefers_geo_structured_providers_for_runtime_local_weather_queries() {
    let contract = weather_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, Some("Anderson, SC"));
    let brave = descriptor_for(SearchProviderStage::BraveHttp);
    let weather_gov = descriptor_for(SearchProviderStage::WeatherGovLocalityDetail);

    let mut descriptors = vec![brave, weather_gov];
    descriptors.sort_by_key(|descriptor| provider_probe_priority_key(&requirements, descriptor));

    assert!(
        matches!(
            descriptors.first().map(|descriptor| descriptor.stage),
            Some(SearchProviderStage::WeatherGovLocalityDetail)
        ),
        "expected geo-structured provider first, got {:?}",
        descriptors
            .iter()
            .map(|descriptor| descriptor.stage)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        descriptors.last().map(|descriptor| descriptor.stage),
        Some(SearchProviderStage::BraveHttp)
    );
}

#[test]
fn google_news_top_stories_rss_url_uses_typed_feed_endpoint() {
    let url = build_google_news_top_stories_rss_url();
    assert_eq!(
        url,
        "https://news.google.com/rss?hl=en-US&gl=US&ceid=US%3Aen"
    );
}

#[test]
fn provider_candidate_usability_requires_observed_sources() {
    let contract = price_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, None);
    let brave = descriptor_for(SearchProviderStage::BraveHttp);

    assert!(!provider_candidate_is_usable(
        &requirements,
        SearchProviderCandidateSelectionInput {
            descriptor: &brave,
            source_count: 0,
            challenge_present: false,
        }
    ));
    assert!(provider_candidate_is_usable(
        &requirements,
        SearchProviderCandidateSelectionInput {
            descriptor: &brave,
            source_count: 1,
            challenge_present: false,
        }
    ));
}

#[test]
fn search_provider_requirements_do_not_request_ordered_collection_for_snapshot_queries() {
    let contract = price_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, None);
    assert_eq!(
        requirements,
        SearchProviderRequirements {
            freshness_bias: true,
            ordered_collection_preferred: false,
            structured_record_preferred: true,
            link_collection_preferred: false,
            canonical_link_out_preferred: false,
            currentness_required: true,
            locality_scope_required: false,
            discovery_surface_required: false,
            geo_scoped_detail_required: false,
            browser_fallback_allowed: true,
        }
    );
}

#[test]
fn search_provider_requirements_default_to_ranked_index_for_non_external_queries() {
    let contract = base_contract();
    let requirements = search_provider_requirements_from_contract(&contract, None);
    assert_eq!(
        requirements,
        SearchProviderRequirements {
            freshness_bias: false,
            ordered_collection_preferred: false,
            structured_record_preferred: false,
            link_collection_preferred: false,
            canonical_link_out_preferred: false,
            currentness_required: false,
            locality_scope_required: false,
            discovery_surface_required: true,
            geo_scoped_detail_required: false,
            browser_fallback_allowed: true,
        }
    );
    let registry = search_provider_registry();
    assert!(registry
        .iter()
        .any(|descriptor| { descriptor.stage == SearchProviderStage::GoogleNewsTopStoriesRss }));
    assert!(registry
        .iter()
        .any(|descriptor| descriptor.stage == SearchProviderStage::RestaurantJiLocalityDirectory));
    assert!(registry
        .iter()
        .any(|descriptor| descriptor.stage == SearchProviderStage::BraveHttp));
}

#[test]
fn search_provider_requirements_prefer_geo_scoped_structured_records_for_local_snapshots() {
    let contract = weather_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, Some("Anderson, SC"));
    assert_eq!(
        requirements,
        SearchProviderRequirements {
            freshness_bias: true,
            ordered_collection_preferred: false,
            structured_record_preferred: true,
            link_collection_preferred: false,
            canonical_link_out_preferred: false,
            currentness_required: true,
            locality_scope_required: true,
            discovery_surface_required: false,
            geo_scoped_detail_required: true,
            browser_fallback_allowed: true,
        }
    );
}

#[test]
fn search_provider_requirements_normalize_direct_weather_snapshots_away_from_discovery_surface() {
    let contract = misclassified_weather_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, Some("Anderson, SC"));

    assert!(
        !requirements.discovery_surface_required,
        "single-record structured weather snapshots should admit direct resolution providers"
    );
}

#[test]
fn search_provider_requirements_prefer_link_collections_for_local_multi_entity_queries() {
    let contract = locality_comparison_contract();
    let requirements = search_provider_requirements_from_contract(&contract, Some("Anderson, SC"));
    assert_eq!(
        requirements,
        SearchProviderRequirements {
            freshness_bias: false,
            ordered_collection_preferred: false,
            structured_record_preferred: false,
            link_collection_preferred: true,
            canonical_link_out_preferred: true,
            currentness_required: false,
            locality_scope_required: true,
            discovery_surface_required: true,
            geo_scoped_detail_required: true,
            browser_fallback_allowed: true,
        }
    );
}

#[test]
fn non_geo_ordered_collection_contracts_do_not_enter_entity_expansion_mode() {
    let contract = misclassified_headline_contract();
    assert!(
        !contract_requires_geo_scoped_entity_expansion(&contract),
        "headline-style ordered collections should not be interpreted as same-domain entity expansion"
    );

    let requirements = search_provider_requirements_from_contract(&contract, None);
    assert!(requirements.ordered_collection_preferred);
}

#[test]
fn provider_admission_uses_structural_requirements_for_local_multi_entity_queries() {
    let contract = locality_comparison_contract();
    let requirements = search_provider_requirements_from_contract(&contract, Some("Anderson, SC"));
    let restaurantji = descriptor_for(SearchProviderStage::RestaurantJiLocalityDirectory);
    let brave = descriptor_for(SearchProviderStage::BraveHttp);
    let google_news = descriptor_for(SearchProviderStage::GoogleNewsRss);
    let google_news_top_stories = descriptor_for(SearchProviderStage::GoogleNewsTopStoriesRss);
    let weather_gov = descriptor_for(SearchProviderStage::WeatherGovLocalityDetail);

    assert!(provider_descriptor_is_admissible(
        &requirements,
        &restaurantji
    ));
    assert!(provider_descriptor_is_admissible(&requirements, &brave));
    assert!(
        !provider_descriptor_is_admissible(&requirements, &google_news),
        "ordered collections without geo-scoped resolution should be inadmissible for locality comparison"
    );
    assert!(
        !provider_descriptor_is_admissible(&requirements, &google_news_top_stories),
        "top-stories ordered collections must not satisfy canonical link-out expansion contracts"
    );
    assert!(
        !provider_descriptor_is_admissible(&requirements, &weather_gov),
        "single detail surfaces without discovery affordances should be inadmissible for multi-entity discovery"
    );
}

#[test]
fn probe_priority_prefers_locality_directory_provider_for_local_multi_entity_queries() {
    let contract = locality_comparison_contract();
    let requirements = search_provider_requirements_from_contract(&contract, Some("Anderson, SC"));
    let restaurantji = descriptor_for(SearchProviderStage::RestaurantJiLocalityDirectory);
    let brave = descriptor_for(SearchProviderStage::BraveHttp);

    let mut descriptors = vec![brave, restaurantji];
    descriptors.sort_by_key(|descriptor| provider_probe_priority_key(&requirements, descriptor));

    assert_eq!(
        descriptors.first().map(|descriptor| descriptor.stage),
        Some(SearchProviderStage::RestaurantJiLocalityDirectory)
    );
    assert_eq!(
        descriptors.last().map(|descriptor| descriptor.stage),
        Some(SearchProviderStage::BraveHttp)
    );
}

#[test]
fn provider_admission_allows_geo_structured_detail_surfaces_for_local_snapshots_even_if_contract_requested_discovery(
) {
    let contract = misclassified_weather_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, Some("Anderson, SC"));
    let weather_gov = descriptor_for(SearchProviderStage::WeatherGovLocalityDetail);

    assert!(provider_descriptor_is_admissible(
        &requirements,
        &weather_gov
    ));
}

#[test]
fn provider_admission_rejects_locality_bound_detail_surfaces_for_global_snapshots() {
    let contract = price_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, None);
    let weather_gov = descriptor_for(SearchProviderStage::WeatherGovLocalityDetail);
    let brave = descriptor_for(SearchProviderStage::BraveHttp);

    assert!(
        !provider_descriptor_is_admissible(&requirements, &weather_gov),
        "global snapshot queries must not admit locality-bound structured providers"
    );
    assert!(provider_descriptor_is_admissible(&requirements, &brave));
}

#[test]
fn provider_admission_allows_queryable_indexes_for_single_entity_geo_detail_queries() {
    let requirements = SearchProviderRequirements {
        freshness_bias: false,
        ordered_collection_preferred: false,
        structured_record_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        currentness_required: false,
        locality_scope_required: true,
        discovery_surface_required: true,
        geo_scoped_detail_required: true,
        browser_fallback_allowed: true,
    };
    let brave = descriptor_for(SearchProviderStage::BraveHttp);

    assert!(
        provider_descriptor_is_admissible(&requirements, &brave),
        "queryable index providers remain admissible for detail lookups"
    );
}

#[test]
fn discovery_backed_selection_prefers_geo_scoped_structured_candidates_for_local_snapshots() {
    let contract = weather_snapshot_contract();
    let requirements = search_provider_requirements_from_contract(&contract, Some("Anderson, SC"));
    let weather_gov = descriptor_for(SearchProviderStage::WeatherGovLocalityDetail);
    let brave = descriptor_for(SearchProviderStage::BraveHttp);

    let mut candidates = [
        SearchProviderCandidateSelectionInput {
            descriptor: &brave,
            source_count: 4,
            challenge_present: false,
        },
        SearchProviderCandidateSelectionInput {
            descriptor: &weather_gov,
            source_count: 1,
            challenge_present: false,
        },
    ];
    candidates.sort_by_key(|candidate| provider_candidate_selection_key(&requirements, *candidate));

    assert!(matches!(
        candidates
            .first()
            .map(|candidate| candidate.descriptor.stage),
        Some(SearchProviderStage::WeatherGovLocalityDetail)
    ));
}

#[test]
fn search_budget_exhaustion_is_time_bounded() {
    let started = now_ms().saturating_sub(EDGE_WEB_SEARCH_TOTAL_BUDGET_MS + 1);
    assert!(search_budget_exhausted(started));
    assert!(!search_budget_exhausted(now_ms()));
}

#[test]
fn ddg_redirect_is_decoded() {
    let href = "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpath%3Fa%3Db%23frag";
    let decoded = normalize_search_href(href).expect("decoded url");
    assert_eq!(decoded, "https://example.com/path?a=b");
}

#[test]
fn google_redirect_is_decoded() {
    let href = "/url?q=https%3A%2F%2Fexample.com%2Fpath%3Fa%3Db%23frag&sa=U&ved=abc";
    let decoded = normalize_google_search_href(href).expect("decoded url");
    assert_eq!(decoded, "https://example.com/path?a=b");
}

#[test]
fn read_extract_structured_metric_rows_from_tabular_detail_pages() {
    let html = r#"
        <html>
            <body>
                <div id="current-conditions">
                    <div class="panel-heading">
                        <h2 class="panel-title">Anderson, Anderson County Airport (KAND)</h2>
                    </div>
                    <div class="panel-body" id="current-conditions-body">
                        <div id="current_conditions-summary">
                            <p class="myforecast-current">Fair</p>
                            <p class="myforecast-current-lrg">65°F</p>
                            <p class="myforecast-current-sm">18°C</p>
                        </div>
                        <div id="current_conditions_detail">
                            <table>
                                <tr><td><b>Humidity</b></td><td>93%</td></tr>
                                <tr><td><b>Wind Speed</b></td><td>SW 3 mph</td></tr>
                                <tr><td><b>Last update</b></td><td>11 Mar 8:56 am EDT</td></tr>
                            </table>
                        </div>
                        <p class="moreInfo">
                            <a id="wxGraph" href="MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical">Hourly Weather Forecast</a>
                        </p>
                    </div>
                </div>
            </body>
        </html>
    "#;
    let (_title, blocks) = extract_read_blocks_for_url(
        "https://forecast.weather.gov/zipcity.php?inputstring=Anderson,SC",
        html,
    );
    let content = blocks.join(" ");

    assert!(content.contains("65°F"));
    assert!(content.contains("18°C"));
    assert!(content.contains("Humidity 93%"));
    assert!(content.contains("Wind Speed SW 3 mph"));
    assert!(content.contains("Last update 11 Mar 8:56 am EDT"));
}

#[test]
fn read_extract_prefers_current_observation_panel_over_forecast_panel_when_both_exist() {
    let html = r#"
        <html>
            <body>
                <div id="current-conditions" class="panel panel-default">
                    <div class="panel-heading">
                        <div>
                            <b>Current conditions at</b>
                            <h2 class="panel-title">Anderson, Anderson County Airport (KAND)</h2>
                        </div>
                    </div>
                    <div class="panel-body" id="current-conditions-body">
                        <div id="current_conditions-summary" class="pull-left">
                            <p class="myforecast-current">Fair</p>
                            <p class="myforecast-current-lrg">84°F</p>
                            <p class="myforecast-current-sm">29°C</p>
                        </div>
                        <div id="current_conditions_detail" class="pull-left">
                            <table>
                                <tr><td><b>Humidity</b></td><td>40%</td></tr>
                                <tr><td><b>Wind Speed</b></td><td>SW 13 mph</td></tr>
                                <tr><td><b>Last update</b></td><td>11 Mar 5:56 pm EDT</td></tr>
                            </table>
                        </div>
                    </div>
                </div>
                <div class="panel-body" id="detailed-forecast-body">
                    <div class="row row-even row-forecast">
                        <div class="col-sm-2 forecast-label"><b>Saturday</b></div>
                        <div class="col-sm-10 forecast-text">Mostly sunny, with a high near 73.</div>
                    </div>
                    <div class="row row-odd row-forecast">
                        <div class="col-sm-2 forecast-label"><b>Sunday</b></div>
                        <div class="col-sm-10 forecast-text">A 30 percent chance of rain after 2pm. Partly sunny, with a high near 72.</div>
                    </div>
                </div>
            </body>
        </html>
    "#;

    let (_title, blocks) = extract_read_blocks_for_url(
        "https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC&site=GSP&textField1=34.5186&textField2=-82.6458&e=0",
        html,
    );
    let content = blocks.join(" ");

    assert!(content.contains("84°F"));
    assert!(content.contains("29°C"));
    assert!(content.contains("Humidity 40%"));
    assert!(content.contains("Wind Speed SW 13 mph"));
    assert!(content.contains("Last update 11 Mar 5:56 pm EDT"));
    assert!(!content.contains("Mostly sunny, with a high near 73."));
}

#[test]
fn parses_minimal_ddg_serp_html() {
    let html = r#"
        <html>
          <body>
            <div class="result">
              <a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa">Example A</a>
              <div class="result__snippet">Snippet A</div>
            </div>
            <div class="result">
              <a class="result__a" href="https://example.com/b">Example B</a>
            </div>
          </body>
        </html>
        "#;
    let sources = parse_ddg_sources_from_html(html, 10);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].url, "https://example.com/a");
    assert_eq!(sources[0].title.as_deref(), Some("Example A"));
    assert_eq!(sources[0].snippet.as_deref(), Some("Snippet A"));
    assert_eq!(sources[0].rank, Some(1));
    assert_eq!(sources[1].url, "https://example.com/b");
    assert_eq!(sources[1].rank, Some(2));
}

#[test]
fn extract_non_html_read_blocks_preserves_metric_payload() {
    let blocks = extract_non_html_read_blocks(
        "Anderson,SC: temp +70°F humidity 66% wind 2mph pressure 1023hPa as of 20:18:01-0500",
    );
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].contains("humidity 66%"));
    assert!(blocks[0].contains("wind 2mph"));
}

#[test]
fn parses_minimal_bing_serp_html() {
    let html = r#"
        <html>
          <body>
            <li class="b_algo">
              <h2><a href="https://example.com/a">Example A</a></h2>
              <div class="b_caption"><p>Snippet A</p></div>
            </li>
            <li class="b_algo">
              <h2><a href="https://example.com/b">Example B</a></h2>
            </li>
          </body>
        </html>
        "#;
    let sources = parse_bing_sources_from_html(html, 10);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].url, "https://example.com/a");
    assert_eq!(sources[0].title.as_deref(), Some("Example A"));
    assert_eq!(sources[0].snippet.as_deref(), Some("Snippet A"));
    assert_eq!(sources[1].url, "https://example.com/b");
    assert_eq!(sources[1].title.as_deref(), Some("Example B"));
}

#[test]
fn parses_minimal_brave_serp_html() {
    let html = r#"
        <html>
          <body>
            <div class="snippet" data-type="web">
              <a class="svelte-14r20fy l1" href="https://example.com/a">Example A</a>
              <div class="generic-snippet"><div class="content">Snippet A</div></div>
            </div>
            <div class="snippet" data-type="web">
              <a class="svelte-14r20fy l1" href="https://example.com/b">Example B</a>
            </div>
          </body>
        </html>
        "#;
    let sources = parse_brave_sources_from_html(html, 10);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].url, "https://example.com/a");
    assert_eq!(sources[0].title.as_deref(), Some("Example A"));
    assert_eq!(sources[0].snippet.as_deref(), Some("Snippet A"));
    assert_eq!(sources[1].url, "https://example.com/b");
}

#[test]
fn serp_parsers_reject_global_anchor_fallbacks_without_result_containers() {
    let html = r#"
        <html>
          <body>
            <nav>
              <a href="https://example.com/nav-only">Nav Link</a>
            </nav>
          </body>
        </html>
        "#;

    assert!(parse_ddg_sources_from_html(html, 10).is_empty());
    assert!(parse_bing_sources_from_html(html, 10).is_empty());
}

#[test]
fn parses_google_news_rss_items() {
    let rss = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Headline One</title>
              <link>https://news.google.com/rss/articles/abc?oc=5&amp;x=1</link>
              <source>Outlet A</source>
            </item>
            <item>
              <title><![CDATA[Headline Two]]></title>
              <link>https://example.com/story-two</link>
            </item>
          </channel>
        </rss>
        "#;

    let sources = parse_google_news_sources_from_rss(rss, 10);
    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources[0].url,
        "https://news.google.com/rss/articles/abc?oc=5&x=1"
    );
    assert_eq!(sources[0].title.as_deref(), Some("Headline One"));
    assert_eq!(sources[0].snippet.as_deref(), Some("Outlet A"));
    assert_eq!(sources[1].url, "https://example.com/story-two");
    assert_eq!(sources[1].title.as_deref(), Some("Headline Two"));
}

#[test]
fn parses_same_host_child_collection_links() {
    let html = r#"
        <html>
          <head>
            <title>Restaurants Anderson South Carolina</title>
            <meta name="description" content="Find the best places to eat in Anderson, SC." />
          </head>
          <body>
            <a href="/sc/anderson/italian/">Italian</a>
            <a href="/sc/anderson/pizza/">Pizza</a>
            <a href="/sc/anderson/brothers-italian-cuisine-/">Brothers Italian Cuisine</a>
          </body>
        </html>
        "#;

    let sources = parse_same_host_child_collection_sources_from_html(
        "https://www.restaurantji.com/sc/anderson/",
        html,
        10,
    );

    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources[0].url,
        "https://www.restaurantji.com/sc/anderson/italian/"
    );
    assert_eq!(sources[0].title.as_deref(), Some("Italian"));
    assert!(sources[0]
        .snippet
        .as_deref()
        .unwrap_or_default()
        .contains("Anderson"));
}

#[test]
fn parses_json_ld_item_list_sources() {
    let html = r#"
        <html>
          <head>
            <title>Italian Restaurants in Anderson, SC</title>
            <meta name="description" content="Best Italian restaurants in Anderson." />
            <script type="application/ld+json">
              {
                "@context":"https://schema.org",
                "@type":"ItemList",
                "itemListElement":[
                  {
                    "@type":"ListItem",
                    "position":1,
                    "item":{
                      "@type":"Restaurant",
                      "name":"Dolce Vita Italian Bistro",
                      "url":"/sc/anderson/dolce-vita-italian-bistro-/",
                      "aggregateRating":{"ratingValue":4.6,"reviewCount":211},
                      "priceRange":"$$"
                    }
                  },
                  {
                    "@type":"ListItem",
                    "position":2,
                    "item":{
                      "@type":"Restaurant",
                      "name":"Coach House Restaurant",
                      "url":"/sc/anderson/coach-house-restaurant-/"
                    }
                  }
                ]
              }
            </script>
          </head>
        </html>
        "#;

    let sources = parse_json_ld_item_list_sources_from_html(
        "https://www.restaurantji.com/sc/anderson/italian/",
        html,
        10,
    );

    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources[0].url,
        "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-/"
    );
    assert_eq!(
        sources[0].title.as_deref(),
        Some("Dolce Vita Italian Bistro")
    );
    assert!(sources[0]
        .snippet
        .as_deref()
        .unwrap_or_default()
        .contains("4.6 rating"));
}

fn parses_generic_page_source_from_html_uses_meta_fallbacks() {
    let html = r#"
        <html>
          <head>
            <meta property="og:title" content="Bitcoin price today, BTC to USD live price, marketcap and chart | CoinDesk">
            <meta property="og:description" content="The price of Bitcoin (BTC) is $68,214.99 today as of Mar 6, 2026, 2:25 pm EST.">
          </head>
          <body></body>
        </html>
        "#;

    let source =
        parse_generic_page_source_from_html("https://www.coindesk.com/price/bitcoin", html)
            .expect("generic page source");

    assert_eq!(
        source.title.as_deref(),
        Some("Bitcoin price today, BTC to USD live price, marketcap and chart | CoinDesk")
    );
    assert!(source
        .snippet
        .as_deref()
        .unwrap_or_default()
        .contains("$68,214.99"));
}

#[test]
fn parses_bing_news_rss_items_and_decodes_article_links() {
    let rss = r#"
        <?xml version="1.0" encoding="utf-8" ?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Headline One</title>
              <link>http://www.bing.com/news/apiclick.aspx?ref=FexRss&amp;url=https%3a%2f%2fexample.com%2fstory-one&amp;c=1</link>
              <description>Summary one.</description>
              <News:Source>Outlet A</News:Source>
            </item>
            <item>
              <title>Headline Two</title>
              <link>https://example.org/story-two</link>
              <description>Summary two.</description>
            </item>
          </channel>
        </rss>
        "#;

    let sources = parse_bing_news_sources_from_rss(rss, 10);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].url, "https://example.com/story-one");
    assert_eq!(sources[0].title.as_deref(), Some("Headline One"));
    assert!(sources[0]
        .snippet
        .as_deref()
        .unwrap_or_default()
        .contains("Outlet A"));
    assert_eq!(sources[1].url, "https://example.org/story-two");
}

#[test]
fn read_extract_builds_quote_spans_with_offsets() {
    let html = r#"
        <html>
          <head><title>Doc</title></head>
          <body>
            <article>
              <p>Hello world.</p>
              <p>Second paragraph.</p>
            </article>
          </body>
        </html>
        "#;
    let (_title, blocks) = extract_read_blocks(html);
    let (content, spans) = build_document_text_and_spans(&blocks, None);
    assert!(content.contains("Hello world."));
    assert!(content.contains("Second paragraph."));
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].quote, "Hello world.");
    assert!(spans[0].end_byte > spans[0].start_byte);
    assert_eq!(
        &content[spans[0].start_byte as usize..spans[0].end_byte as usize],
        spans[0].quote
    );
}

#[test]
fn read_extract_ignores_structured_metadata_noise_blocks() {
    let html = r#"
        <html>
          <head><title>Doc</title></head>
          <body>
            <article>
              <p>{"@context":"https://schema.org","@type":"NewsMediaOrganization","datePublished":"1996-10-07","inLanguage":"en","image":{"@type":"ImageObject","width":1200,"height":630,"caption":"Example"}}</p>
              <p>Top story update: officials announced a new response plan this morning.</p>
            </article>
          </body>
        </html>
        "#;
    let (_title, blocks) = extract_read_blocks(html);
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].contains("Top story update"));
}

#[test]
fn read_extract_ignores_executable_script_noise_blocks() {
    let html = r#"
        <html>
          <head><title>Menu for Coach House Restaurant, Anderson, SC - Restaurantji</title></head>
          <body>
            <article>
              <p>127 E Shockley Ferry Rd, Anderson, SC 29624 (864) 225-0070</p>
              <p>return ([1e7] + -1e3 + -4e3 + -8e3 + -1e11).replace(/[018]/g, c => (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)); document.querySelector('.commentPopup').style.display = 'none'; googletag.cmd.push(function() { googletag.display('restaurantji_com_300x250_1'); });</p>
            </article>
          </body>
        </html>
        "#;

    let (_title, blocks) = extract_read_blocks(html);

    assert_eq!(blocks.len(), 1);
    assert_eq!(
        blocks[0],
        "127 E Shockley Ferry Rd, Anderson, SC 29624 (864) 225-0070"
    );
}

#[test]
fn read_extract_ignores_inline_markup_noise_blocks() {
    let html = r#"
        <html>
          <head><title>Menu for Coach House Restaurant, Anderson, SC - Restaurantji</title></head>
          <body>
            <article>
              <p>127 E Shockley Ferry Rd, Anderson, SC 29624 (864) 225-0070</p>
              <p>org/2000/svg" width="16" height="16" paddingTop="20" viewBox="0 0 24 24"><path d="M24 20"></path></svg></p>
            </article>
          </body>
        </html>
        "#;

    let (_title, blocks) = extract_read_blocks(html);

    assert_eq!(blocks.len(), 1);
    assert_eq!(
        blocks[0],
        "127 E Shockley Ferry Rd, Anderson, SC 29624 (864) 225-0070"
    );
}

#[test]
fn read_extract_prefers_repeating_label_surface_on_curated_collection_pages() {
    let html = r#"
        <html>
          <head><title>Menu for Red Tomato and Wine Restaurant, Anderson, SC - Restaurantji</title></head>
          <body>
            <div class="comment-shell">
              <ul>
                <li>Home</li>
                <li>Restaurants</li>
                <li>Anderson</li>
                <li><script>document.querySelector('.commentPopup').style.display = 'none';</script></li>
              </ul>
            </div>
            <main>
              <h2>Customers' Favorites</h2>
              <div class="tips__link good">Ziti with Meat and Rose Sauce</div>
              <div class="tips__link good">Hummus with Grilled Pita Bread</div>
              <div class="tips__link good">Fettuccine Alfredo with Shrimp</div>
              <div class="tips__link good">Spaghetti with Meat Sauce</div>
              <div class="tips__link good">Three Cheese Manicotti</div>
              <h2>Menu</h2>
              <div class="carusel">
                <a class="gallery_item" href="../gallery/menu/#id=one.jpg" aria-label="View Photo"></a>
                <a class="gallery_item" href="../gallery/menu/#id=two.jpg" aria-label="View Photo"></a>
              </div>
            </main>
          </body>
        </html>
        "#;

    let (_title, blocks) = extract_read_blocks_for_url(
        "https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/",
        html,
    );
    let content = blocks.join(" ");

    assert!(!blocks.is_empty());
    assert!(blocks
        .iter()
        .any(|block| block == "Ziti with Meat and Rose Sauce"));
    assert!(content.contains("Ziti with Meat and Rose Sauce"));
    assert!(content.contains("Fettuccine Alfredo with Shrimp"));
    assert!(!content.contains("Item inventory includes"));
    assert!(!content.contains("document.querySelector"));
    assert!(!content.contains("Home"));
}

#[test]
fn read_extract_prefers_repeating_label_surface_when_featured_labels_are_absent() {
    let html = r#"
        <html>
          <head><title>Menu for Red Tomato and Wine Restaurant, Anderson, SC - Restaurantji</title></head>
          <body>
            <main>
              <h4 class="menu-section">Hero Sandwiches</h4>
              <div class="menu-item"><div class="menu-top"><div class="menu-title">Organic Smoked Ham Hero Sandwich</div></div></div>
              <div class="menu-item"><div class="menu-top"><div class="menu-title">Meatball Hero Sandwich</div></div></div>
              <div class="menu-item"><div class="menu-top"><div class="menu-title">Gourmet Chicken Hero Sandwich</div></div></div>
              <div class="menu-item"><div class="menu-top"><div class="menu-title">Philly Steak &amp; Cheese Hero Sandwich</div></div></div>
              <script>
                document.querySelector('.commentPopup').style.display = 'none';
              </script>
            </main>
          </body>
        </html>
        "#;

    let (_title, blocks) = extract_read_blocks_for_url(
        "https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/",
        html,
    );
    let content = blocks.join(" ");

    assert!(!blocks.is_empty());
    assert!(blocks
        .iter()
        .any(|block| block == "Organic Smoked Ham Hero Sandwich"));
    assert!(content.contains("Organic Smoked Ham Hero Sandwich"));
    assert!(content.contains("Meatball Hero Sandwich"));
    assert!(content.contains("Philly Steak & Cheese Hero Sandwich"));
    assert!(!content.contains("Item inventory includes"));
    assert!(!content.contains("document.querySelector"));
}

#[test]
fn read_extract_prefers_repeating_label_surface_over_prose_heavy_sibling_subtrees() {
    let html = r#"
        <html>
          <head><title>Menu for Brothers Italian Cuisine, Anderson, SC - Restaurantji</title></head>
          <body>
            <main>
              <h2>Customers' Favorites</h2>
              <div class="tips__link good">Brothers Special Shrimp Pasta</div>
              <div class="tips__link good">Chef Salad</div>
              <div class="tips__link good">Italian Stromboli</div>
              <div class="tips__link good">Grilled Chicken Salad</div>
              <div class="tips__link good">Meat Lovers Calzone</div>
              <div id="Comments">
                <section class="recent-reviews">
                  <p>One of Anderson's best Italian restaurants with reliable service, a steady lunch crowd, and consistently good takeout.</p>
                  <p>The dining room is small but people still mention pizza, strombolis, burgers, salads, and sandwiches in long review copy.</p>
                  <p>Regulars note fast pickup times, generous portions, and a 4.6 rating from repeat visits over the last few months.</p>
                </section>
              </div>
            </main>
          </body>
        </html>
        "#;

    let (_title, blocks) = extract_read_blocks_for_url(
        "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/",
        html,
    );
    let content = blocks.join(" ");

    assert!(!blocks.is_empty());
    assert!(blocks
        .iter()
        .any(|block| block == "Brothers Special Shrimp Pasta"));
    assert!(content.contains("Brothers Special Shrimp Pasta"));
    assert!(content.contains("Meat Lovers Calzone"));
    assert!(!content.contains("Item inventory includes"));
    assert!(!content.contains("4.6 rating from repeat visits"));
}

#[test]
fn read_extract_prefers_content_rich_nested_region_over_navigation_shell() {
    let html = r#"
        <html>
          <head><title>NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST</title></head>
          <body>
            <main>
              <div class="banner">
                <p>An official website of the United States government</p>
                <p>Here's how you know</p>
                <ul>
                  <li>Publications</li>
                  <li>What We Do</li>
                  <li>All Topics</li>
                  <li>Advanced communications</li>
                  <li>Artificial intelligence</li>
                </ul>
              </div>
              <div class="content-shell">
                <div class="article-body">
                  <p>August 13, 2024: NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards for federal systems.</p>
                  <p>The standards cover ML-KEM for encryption and ML-DSA plus SLH-DSA for digital signatures, giving agencies concrete migration targets.</p>
                </div>
              </div>
            </main>
          </body>
        </html>
        "#;

    let (_title, blocks) = extract_read_blocks(html);
    let content = blocks.join(" ");

    assert!(content.contains("FIPS 203, FIPS 204 and FIPS 205"));
    assert!(content.contains("ML-KEM"));
    assert!(!content.contains("An official website of the United States government"));
    assert!(!content.contains("Advanced communications"));
}

#[test]
fn read_extract_does_not_let_short_navigation_lists_outscore_article_paragraphs() {
    let html = r#"
        <html>
          <head><title>Document</title></head>
          <body>
            <div class="page-shell">
              <ul>
                <li>Home</li>
                <li>Topics</li>
                <li>News</li>
                <li>Publications</li>
                <li>Contact</li>
                <li>Events</li>
              </ul>
              <section>
                <div class="article">
                  <p>December 8, 2025: These Federal Information Processing Standards are mandatory for federal systems and have been adopted by organizations around the world.</p>
                  <p>NIST’s finalized post-quantum standards include FIPS 203, FIPS 204 and FIPS 205, which standardize ML-KEM, ML-DSA and SLH-DSA.</p>
                </div>
              </section>
            </div>
          </body>
        </html>
        "#;

    let (_title, blocks) = extract_read_blocks(html);

    assert_eq!(blocks.len(), 2);
    assert!(blocks[0].contains("Federal Information Processing Standards"));
    assert!(blocks[1].contains("FIPS 203, FIPS 204 and FIPS 205"));
}

#[test]
fn provider_anchor_policy_rejects_locality_only_overlap() {
    let query = "what's the weather right now in Anderson, SC";
    let sources = vec![test_source(
        "https://www.andersenwindows.com/locations/anderson-sc",
        "Andersen Windows in Anderson, SC",
        "Showroom details and replacement windows.",
    )];

    assert!(!provider_sources_match_query_anchors(query, &sources));
}

#[test]
fn provider_anchor_policy_accepts_semantic_plus_locality_overlap() {
    let query = "what's the weather right now in Anderson, SC";
    let sources = vec![test_source(
        "https://www.weather.com/weather/today/l/Anderson+SC",
        "Current weather in Anderson, SC",
        "Current conditions, temperature, humidity and wind in Anderson.",
    )];

    assert!(provider_sources_match_query_anchors(query, &sources));
}

#[test]
fn provider_anchor_policy_ignores_output_contract_markers_in_query() {
    let query = "Current weather in Anderson, SC right now with sources and UTC timestamp.";
    let sources = vec![
        test_source(
            "https://www.weather.com/weather/today/l/Anderson+SC",
            "Current weather in Anderson, SC",
            "Current conditions, temperature, humidity and wind in Anderson.",
        ),
        test_source(
            "https://example.com/anderson/source-references",
            "Anderson references and sources",
            "UTC timestamp and citation notes for publication metadata.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert!(
        filtered
            .iter()
            .any(|source| source.url.contains("weather.com")),
        "expected semantic weather result to survive anchor filtering: {:?}",
        filtered
            .iter()
            .map(|source| &source.url)
            .collect::<Vec<_>>()
    );
}

#[test]
fn provider_anchor_policy_filters_irrelevant_sources_when_one_match_exists() {
    let query = "what's the weather right now in Anderson, SC";
    let sources = vec![
        test_source(
            "https://www.bestbuy.com/discover-learn/what-does-a-sim-card-do/pcmcat1717534816751",
            "What Does a SIM Card Do? - Best Buy",
            "A SIM card stores subscriber identity information for mobile networks.",
        ),
        test_source(
            "https://www.weather.com/weather/today/l/Anderson+SC",
            "Current weather in Anderson, SC",
            "Current conditions, temperature, humidity and wind in Anderson.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert_eq!(filtered.len(), 1);
    assert!(filtered[0].url.contains("weather.com"));
}

#[test]
fn provider_anchor_policy_rejects_stopword_only_overlap() {
    let query = "what's the weather right now in Anderson, SC";
    let sources = vec![
        test_source(
            "https://english.stackexchange.com/questions/14369/is-wot-wot-or-what-what-an-authentic-british-expression-if-its-supposed-to",
            "Is \"wot wot\" or \"what-what\" an authentic British expression?",
            "Question about usage of \"what-what\" in colloquial English.",
        ),
        test_source(
            "https://www.bestbuy.com/discover-learn/whats-the-difference-between-1080p-full-hd-4k/pcmcat1650917375500",
            "What's the Difference Between 1080p (Full HD) and 4K",
            "Compare display resolutions and panel options.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert!(filtered.is_empty());
}

#[test]
fn provider_anchor_policy_rejects_language_learning_drift_for_local_restaurant_lookup() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.";
    let sources = vec![
        test_source(
            "https://en.wikipedia.org/wiki/Italian_language",
            "Italian language - Wikipedia",
            "History, grammar and phonology of the Italian language.",
        ),
        test_source(
            "https://www.duolingo.com/course/it/en/Learn-Italian",
            "Learn Italian with lessons that work - Duolingo",
            "Online lessons for Italian vocabulary and pronunciation.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert!(
        filtered.is_empty(),
        "expected local restaurant lookup to reject cuisine-language drift: {:?}",
        filtered
            .iter()
            .map(|source| (&source.url, source.title.as_deref().unwrap_or_default()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn provider_anchor_policy_preserves_restaurant_surface_for_local_restaurant_lookup() {
    let query =
        "Find the three best-reviewed Italian restaurants in New York, NY and compare their menus.";
    let sources = vec![
        test_source(
            "https://www.timeout.com/newyork/restaurants/best-italian-restaurants-in-nyc",
            "Best Italian Restaurants in NYC",
            "Restaurant reviews, ratings and menus for top Italian restaurants.",
        ),
        test_source(
            "https://storylearning.com/learn/italian/italian-tips/basic-italian-phrases",
            "83 Basic Italian Phrases - StoryLearning",
            "Learn Italian phrases and grammar basics for beginners.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert_eq!(filtered.len(), 1);
    assert!(filtered[0].url.contains("timeout.com/newyork/restaurants"));
}

#[test]
fn provider_anchor_policy_refuses_weak_overlap_fallback_for_grounded_price_lookup() {
    let query = "What's the current price of Bitcoin?";
    let sources = vec![
        test_source(
            "https://bitco.in/forum/threads/free-crypto-from-swapzone.90645/",
            "Free Crypto from Swapzone | Bitcoin Forum",
            "I want to share a method that made me over $3,000 in 3 days.",
        ),
        test_source(
            "https://bitco.in/forum/threads/free-eth-method.89200/",
            "FREE ETH METHOD | Bitcoin Forum",
            "Free ETH method discussion thread.",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert!(
        filtered.is_empty(),
        "grounded price lookup should not keep weak-overlap forum spam: {:?}",
        filtered
            .iter()
            .map(|source| (&source.url, source.title.as_deref().unwrap_or_default()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn provider_anchor_policy_rejects_community_discussion_surface_for_grounded_price_lookup() {
    let query = "What's the current price of Bitcoin?";
    let sources = vec![test_source(
        "https://community.example.com/discussions/bitcoin-price-outlook",
        "Bitcoin price outlook discussion thread",
        "Community discussion about where the price goes next.",
    )];

    let filtered = filter_provider_sources_by_query_anchors(query, sources);
    assert!(
        filtered.is_empty(),
        "grounded price lookup should not keep community discussion surfaces: {:?}",
        filtered
            .iter()
            .map(|source| (&source.url, source.title.as_deref().unwrap_or_default()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn provider_anchor_policy_keeps_generic_headline_sources_without_strict_anchor_overlap() {
    let query = "today's top news headlines";
    let sources = vec![
        test_source(
            "https://www.reuters.com/world/europe/example-story/",
            "Country leaders meet for emergency summit",
            "Reuters",
        ),
        test_source(
            "https://apnews.com/article/example-story",
            "Major policy vote expected this afternoon",
            "AP News",
        ),
    ];

    let filtered = filter_provider_sources_by_query_anchors(query, sources.clone());
    assert_eq!(filtered.len(), sources.len());
}

#[tokio::test(flavor = "current_thread")]
async fn retrieval_timeout_uses_http_fallback_for_search_flow() {
    let html = retrieve_html_with_fallback(
        "https://duckduckgo.com/?q=latest+news",
        Err(anyhow!(
            "ERROR_CLASS=TimeoutOrHang browser retrieval timed out after 20s"
        )),
        || async {
            Ok(r#"
                <html><body>
                  <div class="result">
                    <a class="result__a" href="https://example.com/a">Result A</a>
                  </div>
                </body></html>
                "#
            .to_string())
        },
    )
    .await
    .expect("fallback should succeed");

    let sources = parse_ddg_sources_from_html(&html, 5);
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].url, "https://example.com/a");
}

#[tokio::test(flavor = "current_thread")]
async fn retrieval_timeout_uses_http_fallback_for_read_flow() {
    let html = retrieve_html_with_fallback(
        "https://example.com/article",
        Err(anyhow!(
            "browser retrieval navigate failed: Request timed out"
        )),
        || async {
            Ok(r#"
                <html><head><title>Doc</title></head>
                <body><article><p>Alpha.</p><p>Beta.</p></article></body></html>
                "#
            .to_string())
        },
    )
    .await
    .expect("fallback should succeed");

    let (title, blocks) = extract_read_blocks(&html);
    assert_eq!(title.as_deref(), Some("Doc"));
    assert_eq!(blocks.len(), 2);
}

#[test]
fn timeout_or_hang_transport_errors_are_classified_for_structured_retry() {
    assert!(transport_error_is_timeout_or_hang(&anyhow!(
        "HTTP fallback request timed out: https://example.com"
    )));
    assert!(transport_error_is_timeout_or_hang(&anyhow!(
        "ERROR_CLASS=TimeoutOrHang browser retrieval timed out after 8s"
    )));
    assert!(!transport_error_is_timeout_or_hang(&anyhow!(
        "HTTP fallback request failed: connection refused"
    )));
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "live network probe for local-business search orchestration"]
async fn edge_web_search_live_returns_local_business_sources_for_scoped_restaurant_query() {
    let browser = ioi_drivers::browser::BrowserDriver::new();
    let contract = locality_comparison_contract();
    let bundle = crate::agentic::web::edge_web_search(
        &browser,
        "best-reviewed Italian restaurants in Anderson, SC",
        Some("Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."),
        &contract,
        10,
    )
    .await
    .expect("live edge_web_search should complete");

    eprintln!("backend={}", bundle.backend);
    eprintln!("query={:?}", bundle.query);
    for source in &bundle.sources {
        eprintln!(
            "source url={} title={:?} snippet={:?}",
            source.url, source.title, source.snippet
        );
    }

    assert!(
        !bundle.sources.is_empty(),
        "expected at least one live source, backend={}",
        bundle.backend
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "live network probe for weather search orchestration"]
async fn edge_web_search_live_returns_weather_sources_for_scoped_weather_query() {
    let browser = ioi_drivers::browser::BrowserDriver::new();
    let contract = weather_snapshot_contract();
    let bundle = crate::agentic::web::edge_web_search(
        &browser,
        "What's the weather like right now?",
        Some("What's the weather like right now in Anderson, SC?"),
        &contract,
        4,
    )
    .await
    .expect("live edge_web_search should complete");

    eprintln!("backend={}", bundle.backend);
    for source in &bundle.sources {
        eprintln!(
            "source url={} title={:?} snippet={:?}",
            source.url, source.title, source.snippet
        );
    }

    assert!(
        bundle
            .sources
            .iter()
            .any(|source| source.url.contains("forecast.weather.gov")),
        "expected weather.gov source, got {:?}",
        bundle
            .sources
            .iter()
            .map(|source| source.url.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        bundle
            .sources
            .iter()
            .any(|source| source.url.contains("wttr.in/")),
        "expected wttr source, got {:?}",
        bundle
            .sources
            .iter()
            .map(|source| source.url.clone())
            .collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "live network probe for price-snapshot search orchestration"]
async fn edge_web_search_live_returns_price_snapshot_sources_for_bitcoin_query() {
    let browser = ioi_drivers::browser::BrowserDriver::new();
    let contract = price_snapshot_contract();
    let bundle = crate::agentic::web::edge_web_search(
        &browser,
        "current Bitcoin price",
        Some("What's the current price of Bitcoin?"),
        &contract,
        10,
    )
    .await
    .expect("live edge_web_search should complete");

    eprintln!("backend={}", bundle.backend);
    eprintln!("query={:?}", bundle.query);
    for source in &bundle.sources {
        eprintln!(
            "source url={} title={:?} snippet={:?}",
            source.url, source.title, source.snippet
        );
    }

    assert!(
        !bundle.sources.is_empty(),
        "expected at least one live source, backend={}",
        bundle.backend
    );
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "live probe for raw Bing HTML retrieval and parser admission"]
async fn bing_http_live_probe_reports_html_shape_and_parser_output() {
    let url = build_bing_serp_url("bitcoin price");
    let html = fetch_html_http_fallback_browser_ua(&url)
        .await
        .expect("live bing html should load");
    let sources = parse_bing_sources_from_html(&html, 10);

    eprintln!("url={}", url);
    eprintln!("html_len={}", html.len());
    eprintln!("contains_b_results={}", html.contains("id=\"b_results\""));
    eprintln!("contains_b_algo={}", html.contains("class=\"b_algo\""));
    eprintln!(
        "contains_ck_redirect={}",
        html.contains("https://www.bing.com/ck/a?!")
    );
    eprintln!("parser_source_count={}", sources.len());
    if let Some(source) = sources.first() {
        eprintln!(
            "first_source url={} title={:?} snippet={:?}",
            source.url, source.title, source.snippet
        );
    }
    let probe_excerpt = html.chars().take(3000).collect::<String>();
    eprintln!("html_excerpt={}", probe_excerpt);
}

#[test]
fn challenge_detection_still_triggers() {
    let reason = detect_human_challenge(
        "https://duckduckgo.com/?q=latest+news",
        "Please verify you are human to continue",
    );
    assert!(reason.is_some());
}

#[test]
fn challenge_detection_flags_cloudflare_interstitial() {
    let reason = detect_human_challenge(
        "https://www.politico.com/news/2026/02/28/iran-strike-democrats-split-message-00806051",
        "Just a moment... Please enable JavaScript and cookies to continue. Cloudflare Ray ID: 123abc",
    );
    assert!(reason.is_some());
}
