use super::*;

fn direct_snapshot_contract() -> WebRetrievalContract {
    WebRetrievalContract {
        contract_version: String::new(),
        entity_cardinality_min: 1,
        comparison_required: false,
        currentness_required: true,
        runtime_locality_required: true,
        source_independence_min: 1,
        citation_count_min: 1,
        structured_record_preferred: true,
        ordered_collection_preferred: false,
        link_collection_preferred: false,
        canonical_link_out_preferred: false,
        geo_scoped_detail_required: true,
        discovery_surface_required: true,
        entity_diversity_required: false,
        scalar_measure_required: true,
        browser_fallback_allowed: true,
    }
}

#[test]
fn lint_normalizes_single_record_snapshot_away_from_discovery_surface() {
    let normalized = lint_web_retrieval_contract(
        "What's the weather like right now near me?",
        Some("What's the weather like right now in Anderson, SC?"),
        direct_snapshot_contract(),
    )
    .expect("contract should lint");

    assert_eq!(normalized.contract_version, WEB_RETRIEVAL_CONTRACT_VERSION);
    assert_eq!(normalized.source_independence_min, 1);
    assert!(
        !normalized.discovery_surface_required,
        "single-record structured snapshots should not force discovery surfaces"
    );
}

#[test]
fn lint_demotes_non_geo_entity_expansion_when_ordered_collection_is_requested() {
    let mut contract = direct_snapshot_contract();
    contract.entity_cardinality_min = 5;
    contract.comparison_required = true;
    contract.currentness_required = true;
    contract.runtime_locality_required = false;
    contract.structured_record_preferred = false;
    contract.ordered_collection_preferred = true;
    contract.link_collection_preferred = true;
    contract.canonical_link_out_preferred = true;
    contract.discovery_surface_required = true;
    contract.entity_diversity_required = true;

    let normalized =
        lint_web_retrieval_contract("Top headlines today", Some("Top headlines today"), contract)
            .expect("contract should lint");

    assert!(normalized.ordered_collection_preferred);
    assert!(!normalized.entity_diversity_required);
    assert!(!normalized.link_collection_preferred);
    assert!(!normalized.canonical_link_out_preferred);
}

#[test]
fn lint_preserves_geo_scoped_entity_expansion_over_ordered_collection() {
    let mut contract = direct_snapshot_contract();
    contract.entity_cardinality_min = 3;
    contract.comparison_required = true;
    contract.currentness_required = false;
    contract.runtime_locality_required = true;
    contract.structured_record_preferred = false;
    contract.ordered_collection_preferred = true;
    contract.link_collection_preferred = true;
    contract.canonical_link_out_preferred = true;
    contract.discovery_surface_required = true;
    contract.geo_scoped_detail_required = true;
    contract.entity_diversity_required = true;

    let normalized = lint_web_retrieval_contract(
        "Find the three best-reviewed Italian restaurants near me and compare their menus.",
        Some("Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."),
        contract,
    )
    .expect("contract should lint");

    assert!(!normalized.ordered_collection_preferred);
    assert!(normalized.entity_diversity_required);
    assert!(normalized.link_collection_preferred);
    assert!(normalized.canonical_link_out_preferred);
}

#[test]
fn lint_demotes_document_briefing_comparison_scaffolding_without_explicit_compare() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = WebRetrievalContract {
        contract_version: WEB_RETRIEVAL_CONTRACT_VERSION.to_string(),
        entity_cardinality_min: 3,
        comparison_required: true,
        currentness_required: true,
        runtime_locality_required: false,
        source_independence_min: 3,
        citation_count_min: 1,
        structured_record_preferred: false,
        ordered_collection_preferred: false,
        link_collection_preferred: true,
        canonical_link_out_preferred: true,
        geo_scoped_detail_required: false,
        discovery_surface_required: true,
        entity_diversity_required: true,
        scalar_measure_required: false,
        browser_fallback_allowed: true,
    };

    let normalized =
        lint_web_retrieval_contract(query, Some(query), contract).expect("contract should lint");

    assert_eq!(normalized.entity_cardinality_min, 1);
    assert_eq!(normalized.source_independence_min, 2);
    assert!(!normalized.comparison_required);
    assert!(!normalized.entity_diversity_required);
    assert!(!normalized.link_collection_preferred);
    assert!(!normalized.canonical_link_out_preferred);
    assert!(!normalized.ordered_collection_preferred);
    assert!(normalized.discovery_surface_required);
}

#[test]
fn semantic_alignment_requirement_tracks_subject_sensitive_contracts() {
    let mut contract = direct_snapshot_contract();
    contract.scalar_measure_required = false;
    contract.currentness_required = false;
    contract.source_independence_min = 1;
    assert!(!contract_requires_semantic_source_alignment(&contract));

    contract.scalar_measure_required = true;
    assert!(contract_requires_semantic_source_alignment(&contract));

    contract.scalar_measure_required = false;
    contract.entity_diversity_required = true;
    assert!(contract_requires_semantic_source_alignment(&contract));
}

#[test]
fn semantic_alignment_requirement_skips_generic_ordered_collections() {
    let mut contract = direct_snapshot_contract();
    contract.entity_cardinality_min = 5;
    contract.currentness_required = true;
    contract.source_independence_min = 5;
    contract.scalar_measure_required = false;
    contract.ordered_collection_preferred = true;
    contract.discovery_surface_required = true;
    contract.structured_record_preferred = false;

    assert!(!contract_requires_semantic_source_alignment(&contract));

    contract.scalar_measure_required = true;
    assert!(contract_requires_semantic_source_alignment(&contract));
}

#[test]
fn deterministic_contract_prefers_direct_snapshot_surfaces_for_local_current_snapshot_queries() {
    let contract = deterministic_web_retrieval_contract(
        "What's the weather like right now near me?",
        Some("What's the weather like right now in Anderson, SC?"),
    );

    assert_eq!(contract.entity_cardinality_min, 1);
    assert!(contract.currentness_required);
    assert!(contract.runtime_locality_required);
    assert!(contract.structured_record_preferred);
    assert!(contract.geo_scoped_detail_required);
    assert!(!contract.ordered_collection_preferred);
    assert!(!contract.discovery_surface_required);
}

#[test]
fn deterministic_contract_prefers_direct_snapshot_surfaces_for_explicit_local_weather_queries() {
    let contract = deterministic_web_retrieval_contract(
        "What's the weather like right now in Anderson, SC?",
        Some("What's the weather like right now in Anderson, SC?"),
    );

    assert_eq!(contract.entity_cardinality_min, 1);
    assert!(contract.currentness_required);
    assert!(!contract.runtime_locality_required);
    assert!(contract.structured_record_preferred);
    assert!(contract.geo_scoped_detail_required);
    assert!(!contract.ordered_collection_preferred);
    assert!(!contract.discovery_surface_required);
}

#[test]
fn deterministic_contract_prefers_direct_snapshot_surfaces_for_subject_currentness_queries() {
    let contract = deterministic_web_retrieval_contract(
        "Who is the current Secretary-General of the UN?",
        Some("Who is the current Secretary-General of the UN?"),
    );

    assert_eq!(contract.entity_cardinality_min, 1);
    assert!(contract.currentness_required);
    assert!(!contract.runtime_locality_required);
    assert!(contract.structured_record_preferred);
    assert!(!contract.geo_scoped_detail_required);
    assert!(!contract.ordered_collection_preferred);
    assert!(!contract.discovery_surface_required);
}

#[test]
fn semantic_alignment_rejects_weather_news_for_local_current_snapshot_queries() {
    let contract = deterministic_web_retrieval_contract(
        "What's the weather like right now near me?",
        Some("What's the weather like right now in Anderson, SC?"),
    );
    let sources = vec![
        WebSource {
            source_id: "weather-news".to_string(),
            rank: Some(1),
            url: "https://example.com/weather/advisory-story".to_string(),
            title: Some("Winter weather advisory expands across the Upstate".to_string()),
            snippet: Some(
                "Anderson County remains under a weather advisory overnight as a cold front moves through."
                    .to_string(),
            ),
            domain: Some("example.com".to_string()),
        },
        WebSource {
            source_id: "weather-record".to_string(),
            rank: Some(2),
            url: "https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC"
                .to_string(),
            title: Some("Anderson, SC current conditions".to_string()),
            snippet: Some(
                "Current conditions: temperature 62 F, humidity 42%, wind 4 mph, observed at 2:00 PM."
                    .to_string(),
            ),
            domain: Some("forecast.weather.gov".to_string()),
        },
    ];

    let aligned = query_matching_source_urls(
        "What's the weather like right now in Anderson, SC?",
        &contract,
        &sources,
    )
    .expect("alignment should succeed");

    assert_eq!(
        aligned,
        vec!["https://forecast.weather.gov/MapClick.php?CityName=Anderson&state=SC"]
    );
}

#[test]
fn semantic_alignment_accepts_current_role_holder_sources_for_subject_currentness_queries() {
    let query = "Who is the current Secretary-General of the UN?";
    let contract = deterministic_web_retrieval_contract(query, Some(query));
    let sources = vec![
        WebSource {
            source_id: "leaders-meet".to_string(),
            rank: Some(1),
            url: "https://example.com/world/leaders-meet-for-summit".to_string(),
            title: Some("Country leaders meet for emergency summit".to_string()),
            snippet: Some(
                "World leaders will gather tomorrow for an emergency summit in Geneva.".to_string(),
            ),
            domain: Some("example.com".to_string()),
        },
        WebSource {
            source_id: "un-bio".to_string(),
            rank: Some(2),
            url: "https://www.un.org/sg/en/content/sg/biography".to_string(),
            title: Some("Secretary-General biography | United Nations".to_string()),
            snippet: Some(
                "António Guterres currently serves as the Secretary-General of the United Nations."
                    .to_string(),
            ),
            domain: Some("un.org".to_string()),
        },
    ];

    let aligned =
        query_matching_source_urls(query, &contract, &sources).expect("alignment should succeed");

    assert_eq!(
        aligned,
        vec!["https://www.un.org/sg/en/content/sg/biography".to_string()]
    );
}

#[test]
fn semantic_alignment_keeps_authority_identifier_pages_for_document_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let sources = vec![
        WebSource {
            source_id: "ir8413".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "NIST IR 8413 Update 1 references FIPS 203, FIPS 204, and FIPS 205 as the finalized post-quantum cryptography standards."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "fips203".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some(
                "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "Federal Information Processing Standard FIPS 203 specifies ML-KEM as a finalized NIST post-quantum cryptography standard."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "fips204".to_string(),
            rank: Some(3),
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some(
                "FIPS 204, Module-Lattice-Based Digital Signature Standard | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "Federal Information Processing Standard FIPS 204 specifies ML-DSA as a finalized NIST post-quantum cryptography standard."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "fips205".to_string(),
            rank: Some(4),
            url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
            title: Some(
                "FIPS 205, Stateless Hash-Based Digital Signature Standard | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "Federal Information Processing Standard FIPS 205 specifies SLH-DSA as a finalized NIST post-quantum cryptography standard."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
    ];

    let aligned =
        query_matching_source_urls(query, &contract, &sources).expect("alignment should succeed");

    assert!(aligned.contains(&"https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()));
    assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/203/final".to_string()));
    assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/204/final".to_string()));
    assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/205/final".to_string()));
}

#[test]
fn semantic_alignment_keeps_authority_overview_pages_for_full_document_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let sources = vec![
        WebSource {
            source_id: "ir8413upd1".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "NIST IR 8413 Update 1 references FIPS 203, FIPS 204, and FIPS 205 as the finalized post-quantum cryptography standards."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "ir8413final".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "NIST documents the post-quantum cryptography standardization process and the selected algorithms."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "selected-algorithms".to_string(),
            rank: Some(3),
            url: "https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms".to_string(),
            title: Some("Post-Quantum Cryptography | CSRC".to_string()),
            snippet: Some(
                "The selected algorithms page links the NIST post-quantum cryptography project to FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "fips204".to_string(),
            rank: Some(4),
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some(
                "FIPS 204, Module-Lattice-Based Digital Signature Standard | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "Federal Information Processing Standard FIPS 204 specifies ML-DSA as a finalized NIST post-quantum cryptography standard."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "fips205".to_string(),
            rank: Some(5),
            url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
            title: Some(
                "FIPS 205, Stateless Hash-Based Digital Signature Standard | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "Federal Information Processing Standard FIPS 205 specifies SLH-DSA as a finalized NIST post-quantum cryptography standard."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
    ];

    let mut aligned =
        query_matching_source_urls(query, &contract, &sources).expect("alignment should succeed");
    let mut expected = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        "https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms".to_string(),
        "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
    ];
    aligned.sort();
    expected.sort();

    assert_eq!(aligned, expected);
}

#[test]
fn semantic_alignment_keeps_authority_identifier_pages_when_live_read_payloads_lack_snippets() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let sources = vec![
        WebSource {
            source_id: "ir8413upd1".to_string(),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: None,
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: "ir8413final".to_string(),
            rank: Some(2),
            url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: None,
            domain: Some("csrc.nist.gov".to_string()),
        },
    ];

    let aligned =
        query_matching_source_urls(query, &contract, &sources).expect("alignment should succeed");

    assert_eq!(
        aligned,
        vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        ]
    );
}

#[test]
fn derived_contract_marks_latest_plural_briefing_queries_as_document_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");

    assert_eq!(contract.entity_cardinality_min, 1);
    assert_eq!(contract.source_independence_min, 2);
    assert_eq!(contract.citation_count_min, 2);
    assert!(contract.currentness_required);
    assert!(!contract.comparison_required);
    assert!(!contract.structured_record_preferred);
    assert!(!contract.ordered_collection_preferred);
    assert!(!contract.entity_diversity_required);
    assert!(contract.discovery_surface_required);
    assert!(!contract.browser_fallback_allowed);
}

#[test]
fn derived_contract_preserves_document_briefing_shape_when_query_contract_is_present() {
    let query = "nist post quantum cryptography standards";
    let query_contract =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = derive_web_retrieval_contract(query, Some(query_contract)).expect("contract");

    assert_eq!(contract.entity_cardinality_min, 1);
    assert_eq!(contract.source_independence_min, 2);
    assert!(contract.currentness_required);
    assert!(!contract.structured_record_preferred);
    assert!(contract.discovery_surface_required);
    assert!(!contract.browser_fallback_allowed);
}

#[test]
fn normalized_contract_restores_runtime_locality_for_scope_resolved_restaurant_query() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let query_contract =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let incoming = WebRetrievalContract {
        contract_version: WEB_RETRIEVAL_CONTRACT_VERSION.to_string(),
        entity_cardinality_min: 3,
        comparison_required: true,
        currentness_required: false,
        runtime_locality_required: false,
        source_independence_min: 3,
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
    };

    let normalized = normalize_web_retrieval_contract(query, Some(query_contract), incoming)
        .expect("contract should normalize");

    assert_eq!(normalized.entity_cardinality_min, 3);
    assert!(normalized.comparison_required);
    assert!(normalized.runtime_locality_required);
    assert!(normalized.geo_scoped_detail_required);
    assert!(normalized.entity_diversity_required);
    assert!(normalized.link_collection_preferred);
    assert!(normalized.canonical_link_out_preferred);
    assert!(normalized.discovery_surface_required);
    assert_eq!(normalized.source_independence_min, 3);
}

#[test]
fn semantic_alignment_accepts_geo_scoped_restaurant_directory_category_sources() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let query_contract =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let contract = derive_web_retrieval_contract(query, Some(query_contract)).expect("contract");
    let sources = vec![WebSource {
        source_id: "restaurantji-italian".to_string(),
        rank: Some(1),
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        title: Some("Italian".to_string()),
        snippet: Some(
            "Find the best places to eat in Anderson, SC with menus, reviews and photos."
                .to_string(),
        ),
        domain: Some("restaurantji.com".to_string()),
    }];

    let aligned =
        query_matching_source_urls(query_contract, &contract, &sources).expect("alignment");

    assert_eq!(
        aligned,
        vec!["https://www.restaurantji.com/sc/anderson/italian/"]
    );
}

#[test]
fn semantic_alignment_rejects_wrong_cuisine_local_business_sources() {
    let query = "Find the three best-reviewed Italian restaurants near me and compare their menus.";
    let query_contract =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let contract = derive_web_retrieval_contract(query, Some(query_contract)).expect("contract");
    let sources = vec![
        WebSource {
            source_id: "restaurantji-fast-food".to_string(),
            rank: Some(1),
            url: "https://www.restaurantji.com/sc/anderson/fast-food/".to_string(),
            title: Some("Fast Food".to_string()),
            snippet: Some(
                "Find the best places to eat in Anderson, SC with menus, reviews and photos."
                    .to_string(),
            ),
            domain: Some("restaurantji.com".to_string()),
        },
        WebSource {
            source_id: "restaurantji-american".to_string(),
            rank: Some(2),
            url: "https://www.restaurantji.com/sc/anderson/american/".to_string(),
            title: Some("American".to_string()),
            snippet: Some(
                "Find the best places to eat in Anderson, SC with menus, reviews and photos."
                    .to_string(),
            ),
            domain: Some("restaurantji.com".to_string()),
        },
    ];

    let aligned =
        query_matching_source_urls(query_contract, &contract, &sources).expect("alignment");

    assert!(aligned.is_empty());
}

#[test]
fn semantic_alignment_accepts_representative_nist_pqc_briefing_sources() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let sources = vec![
        WebSource {
            source_id: "nist-finalized".to_string(),
            rank: Some(1),
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            title: Some(
                "NIST releases first 3 finalized post-quantum encryption standards"
                    .to_string(),
            ),
            snippet: Some(
                "NIST finalized FIPS 203, FIPS 204 and FIPS 205 for post-quantum cryptography."
                    .to_string(),
            ),
            domain: Some("nist.gov".to_string()),
        },
        WebSource {
            source_id: "ibm-summary".to_string(),
            rank: Some(2),
            url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            title: Some("NIST’s post-quantum cryptography standards are here".to_string()),
            snippet: Some(
                "IBM summarized the NIST post-quantum standards ML-KEM, ML-DSA and SLH-DSA."
                    .to_string(),
            ),
            domain: Some("research.ibm.com".to_string()),
        },
        WebSource {
            source_id: "nist-hqc".to_string(),
            rank: Some(3),
            url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
            title: Some(
                "NIST selects HQC as fifth algorithm for post-quantum encryption".to_string(),
            ),
            snippet: Some(
                "NIST selected HQC as a backup algorithm in the post-quantum cryptography standards effort."
                    .to_string(),
            ),
            domain: Some("nist.gov".to_string()),
        },
    ];

    let aligned =
        query_matching_source_urls(query, &contract, &sources).expect("alignment should work");

    assert_eq!(aligned.len(), 3, "aligned_urls={aligned:?}");
    assert!(aligned
        .iter()
        .any(|url| url.contains("finalized-post-quantum-encryption-standards")));
    assert!(aligned
        .iter()
        .any(|url| url.contains("research.ibm.com/blog/nist-pqc-standards")));
    assert!(aligned
        .iter()
        .any(|url| url.contains("nist-selects-hqc-fifth-algorithm")));
}

#[test]
fn semantic_alignment_rejects_off_topic_nist_csf_article_for_full_research_contract() {
    let query_contract =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let contract =
        derive_web_retrieval_contract(query_contract, Some(query_contract)).expect("contract");
    let sources = vec![WebSource {
        source_id: "ibm-csf".to_string(),
        rank: Some(1),
        url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
            .to_string(),
        title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
        snippet: Some(
            "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                .to_string(),
        ),
        domain: Some("www.ibm.com".to_string()),
    }];

    let aligned = query_matching_source_urls(query_contract, &contract, &sources)
        .expect("alignment should work");

    assert!(aligned.is_empty(), "aligned_urls={aligned:?}");
}

#[test]
fn semantic_alignment_resolves_google_news_wrappers_to_canonical_source_urls() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = derive_web_retrieval_contract(query, Some(query)).expect("contract");
    let sources = vec![WebSource {
        source_id: "google-wrapper".to_string(),
        rank: Some(1),
        url: "https://news.google.com/rss/articles/CBMiUkFVX3lxTE0x?oc=5".to_string(),
        title: Some(
            "NIST releases first 3 finalized post-quantum encryption standards".to_string(),
        ),
        snippet: Some(
            "Google News | source_url=https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
        ),
        domain: Some("news.google.com".to_string()),
    }];

    let aligned =
        query_matching_source_urls(query, &contract, &sources).expect("alignment should work");

    assert_eq!(
        aligned,
        vec![
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
        ]
    );
}
