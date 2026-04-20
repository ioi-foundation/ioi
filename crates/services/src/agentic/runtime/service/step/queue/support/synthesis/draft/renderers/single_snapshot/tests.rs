use ioi_types::app::agentic::WebRetrievalContract;

use super::*;

#[test]
fn render_single_snapshot_layout_omits_unread_citations() {
    let mut citations_by_id = BTreeMap::new();
    citations_by_id.insert(
        "c1".to_string(),
        CitationCandidate {
            id: "c1".to_string(),
            url: "https://www.worldcoinindex.com/coin/bitcoin".to_string(),
            source_label: "Bitcoin price | index, chart and news | WorldCoinIndex".to_string(),
            excerpt: "Bitcoin price right now: $86,743.63 USD.".to_string(),
            timestamp_utc: "2026-03-11T13:42:57Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );
    citations_by_id.insert(
        "c2".to_string(),
        CitationCandidate {
            id: "c2".to_string(),
            url: "https://crypto.com/us/price/bitcoin".to_string(),
            source_label: "Bitcoin price - Crypto.com".to_string(),
            excerpt: "BTC price now: $86,744 USD.".to_string(),
            timestamp_utc: "2026-03-11T13:42:57Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: false,
        },
    );

    let draft = SynthesisDraft {
        query: "What's the current price of Bitcoin?".to_string(),
        retrieval_contract: Some(WebRetrievalContract {
            contract_version: "test.v1".to_string(),
            entity_cardinality_min: 1,
            comparison_required: false,
            currentness_required: true,
            runtime_locality_required: false,
            source_independence_min: 1,
            citation_count_min: 2,
            structured_record_preferred: true,
            ordered_collection_preferred: false,
            link_collection_preferred: false,
            canonical_link_out_preferred: false,
            geo_scoped_detail_required: false,
            discovery_surface_required: false,
            entity_diversity_required: false,
            scalar_measure_required: true,
            browser_fallback_allowed: true,
        }),
        run_date: "2026-03-11".to_string(),
        run_timestamp_ms: 1_773_236_577_000,
        run_timestamp_iso_utc: "2026-03-11T13:42:57Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![StoryDraft {
            title: "Bitcoin".to_string(),
            what_happened: "Bitcoin price right now: $86,743.63 USD.".to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec!["c1".to_string(), "c2".to_string()],
            confidence: "high".to_string(),
            caveat: "timestamps may reflect retrieval time".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let rendered = render_single_snapshot_layout(&draft, 1, 2, &BTreeSet::new(), &[], &[], &[]);

    assert!(rendered.contains("https://www.worldcoinindex.com/coin/bitcoin"));
    assert!(!rendered.contains("https://crypto.com/us/price/bitcoin"));
}

#[test]
fn render_single_snapshot_layout_aggregates_read_backed_citations_across_stories() {
    let mut citations_by_id = BTreeMap::new();
    citations_by_id.insert(
        "c1".to_string(),
        CitationCandidate {
            id: "c1".to_string(),
            url: "https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC&site=GSP&textField1=34.5186&textField2=-82.6458&e=0".to_string(),
            source_label: "National Weather Service".to_string(),
            excerpt: "Current conditions as of 8:56 am EDT: temperature 65°F, humidity 93%, wind SW 3 mph.".to_string(),
            timestamp_utc: "2026-03-11T13:19:18Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );
    citations_by_id.insert(
        "c2".to_string(),
        CitationCandidate {
            id: "c2".to_string(),
            url: "https://www.timeanddate.com/weather/usa/anderson".to_string(),
            source_label: "Weather for Anderson, South Carolina, USA".to_string(),
            excerpt: "Current weather: 64°F, fair, wind 4 mph.".to_string(),
            timestamp_utc: "2026-03-11T13:19:18Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );

    let draft = SynthesisDraft {
        query: "What's the weather like right now in Anderson, SC?".to_string(),
        retrieval_contract: Some(WebRetrievalContract {
            contract_version: "test.v1".to_string(),
            entity_cardinality_min: 1,
            comparison_required: false,
            currentness_required: true,
            runtime_locality_required: true,
            source_independence_min: 2,
            citation_count_min: 2,
            structured_record_preferred: true,
            ordered_collection_preferred: false,
            link_collection_preferred: false,
            canonical_link_out_preferred: false,
            geo_scoped_detail_required: true,
            discovery_surface_required: false,
            entity_diversity_required: false,
            scalar_measure_required: true,
            browser_fallback_allowed: true,
        }),
        run_date: "2026-03-11".to_string(),
        run_timestamp_ms: 1_773_236_577_000,
        run_timestamp_iso_utc: "2026-03-11T13:19:18Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![
            StoryDraft {
                title: "National Weather Service".to_string(),
                what_happened:
                    "Current conditions from retrieved source text: temperature 65°F, humidity 93%, wind SW 3 mph."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c1".to_string()],
                confidence: "high".to_string(),
                caveat: "retrieved_utc".to_string(),
            },
            StoryDraft {
                title: "Time and Date".to_string(),
                what_happened:
                    "Current conditions from retrieved source text: 64°F, fair, wind 4 mph."
                        .to_string(),
                changed_last_hour: String::new(),
                why_it_matters: String::new(),
                user_impact: String::new(),
                workaround: String::new(),
                eta_confidence: "high".to_string(),
                citation_ids: vec!["c2".to_string()],
                confidence: "high".to_string(),
                caveat: "retrieved_utc".to_string(),
            },
        ],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let rendered = render_single_snapshot_layout(
        &draft,
        1,
        2,
        &query_metric_axes(&draft.query),
        &[],
        &[],
        &[],
    );

    assert!(rendered.contains("https://forecast.weather.gov/MapClick.php"));
    assert!(rendered.contains("https://www.timeanddate.com/weather/usa/anderson"));
}

#[test]
fn render_single_snapshot_layout_surfaces_direct_current_fact_without_metric_caveats() {
    let mut citations_by_id = BTreeMap::new();
    citations_by_id.insert(
        "c1".to_string(),
        CitationCandidate {
            id: "c1".to_string(),
            url: "https://ask.un.org/faq/14625".to_string(),
            source_label:
                "UN Ask DAG ask.un.org \u{203a} faq \u{203a} 14625 Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                    .to_string(),
            excerpt:
                "Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                    .to_string(),
            timestamp_utc: "2026-04-14T21:08:14Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );

    let draft = SynthesisDraft {
        query: "Who is the current Secretary-General of the UN?".to_string(),
        retrieval_contract: Some(WebRetrievalContract {
            contract_version: "test.v1".to_string(),
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
            scalar_measure_required: false,
            browser_fallback_allowed: true,
        }),
        run_date: "2026-04-14".to_string(),
        run_timestamp_ms: 1_776_200_894_000,
        run_timestamp_iso_utc: "2026-04-14T21:08:14Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![StoryDraft {
            title: "United Nations".to_string(),
            what_happened:
                "Current answer from retrieved source text: Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                    .to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec!["c1".to_string()],
            confidence: "high".to_string(),
            caveat: "retrieved_utc".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let rendered = render_single_snapshot_layout(&draft, 1, 1, &BTreeSet::new(), &[], &[], &[]);

    assert!(rendered.contains("Current snapshot (as of 2026-04-14T21:08:14Z UTC):"));
    assert!(rendered.contains(
        "Current answer: Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
    ));
    assert!(!rendered.contains("Current metric status:"));
    assert!(!rendered.contains(
        "Data caveat: Retrieved source snippets did not expose numeric current-condition metrics"
    ));
}

#[test]
fn render_single_snapshot_layout_keeps_strong_price_snapshot_concise() {
    let mut citations_by_id = BTreeMap::new();
    citations_by_id.insert(
        "c1".to_string(),
        CitationCandidate {
            id: "c1".to_string(),
            url: "https://openai.com/api/pricing/".to_string(),
            source_label: "OpenAI API Pricing | OpenAI".to_string(),
            excerpt: "Pricing: Audio: $32.00 for inputs $0.40 for cached inputs $64.00 for outputs Text: $4.00 for inputs $0.40 for cached inputs $16.00 for outputs".to_string(),
            timestamp_utc: "2026-04-15T06:04:04Z".to_string(),
            note: "retrieved_utc".to_string(),
            from_successful_read: true,
        },
    );

    let draft = SynthesisDraft {
        query: "What is the latest OpenAI API pricing?".to_string(),
        retrieval_contract: Some(WebRetrievalContract {
            contract_version: "test.v1".to_string(),
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
        }),
        run_date: "2026-04-15".to_string(),
        run_timestamp_ms: 1_776_233_044_000,
        run_timestamp_iso_utc: "2026-04-15T06:04:04Z".to_string(),
        completion_reason: "min_sources_reached".to_string(),
        overall_confidence: "high".to_string(),
        overall_caveat: "retrieval receipts available".to_string(),
        stories: vec![StoryDraft {
            title: "OpenAI API Pricing".to_string(),
            what_happened: "Current pricing from retrieved source text: Pricing: Audio: $32.00 for inputs $0.40 for cached inputs $64.00 for outputs Text: $4.00 for inputs $0.40 for cached inputs $16.00 for outputs".to_string(),
            changed_last_hour: String::new(),
            why_it_matters: String::new(),
            user_impact: String::new(),
            workaround: String::new(),
            eta_confidence: "high".to_string(),
            citation_ids: vec!["c1".to_string()],
            confidence: "high".to_string(),
            caveat: "retrieved_utc".to_string(),
        }],
        citations_by_id,
        blocked_urls: Vec::new(),
        partial_note: None,
    };

    let rendered = render_single_snapshot_layout(
        &draft,
        1,
        1,
        &query_metric_axes(&draft.query),
        &[],
        &[],
        &[],
    );

    assert!(rendered.contains("Current pricing from retrieved source text:"));
    assert!(rendered.contains("Audio: $32.00 input, $0.40 cached input, $64.00 output"));
    assert!(rendered.contains("Text: $4.00 input, $0.40 cached input, $16.00 output"));
    assert!(!rendered.contains("Estimated-right-now:"));
    assert!(!rendered.contains("Current metric status:"));
    assert!(!rendered.contains("Data caveat:"));
    assert!(!rendered.contains("(From OpenAI API Pricing"));
}
