use super::*;

#[test]
fn document_briefing_quality_observation_does_not_require_identifier_bearing_sources() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let selected_urls = vec![
        "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption"
            .to_string(),
        "https://www.ibm.com/think/insights/post-quantum-cryptography-transition".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("NIST selects HQC as fifth algorithm for post-quantum encryption".to_string()),
            excerpt:
                "March 11, 2025 - NIST selects HQC as a fifth algorithm for post-quantum encryption."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("Post-quantum cryptography transition guidance".to_string()),
            excerpt:
                "March 2026 - IBM explains recent NIST post-quantum cryptography transition planning for enterprises."
                    .to_string(),
        },
    ];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        2,
        &selected_urls,
        &source_hints,
        None,
    );

    assert!(!observation.identifier_evidence_required);
    assert_eq!(observation.identifier_bearing_sources, 0);
    assert_eq!(observation.required_identifier_label_coverage, 0);
    assert!(observation.identifier_coverage_floor_met);
    assert!(observation.missing_identifier_urls.is_empty());
}

#[test]
fn document_briefing_quality_observation_requires_evidence_backed_identifier_inventory() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let selected_urls = vec![
        "https://www.nist.gov/pqc".to_string(),
        "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            excerpt:
                "December 8, 2025 - Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 are mandatory for federal systems."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("NIST's post-quantum cryptography standards are here - IBM Research".to_string()),
            excerpt:
                "September 18, 2025 - NIST released Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 for ML-KEM, ML-DSA, and SLH-DSA."
                    .to_string(),
        },
    ];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        2,
        &selected_urls,
        &source_hints,
        None,
    );

    assert!(observation.identifier_evidence_required);
    assert_eq!(observation.identifier_bearing_sources, 2);
    assert_eq!(observation.authority_identifier_sources, 1);
    assert_eq!(observation.required_identifier_label_coverage, 3);
    assert!(observation.identifier_coverage_floor_met);
    assert!(observation.quality_floor_met);
    assert!(observation.missing_identifier_urls.is_empty());
}

#[test]
fn document_briefing_quality_observation_rejects_grounded_same_authority_selection_when_distinct_domain_floor_is_required(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
        .expect("retrieval contract");
    let selected_urls = vec![
        "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
        "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard".to_string(),
            ),
            excerpt:
                "NIST finalized FIPS 203 as a post-quantum cryptography standard based on ML-KEM."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("FIPS 204 Module-Lattice-Based Digital Signature Standard".to_string()),
            excerpt:
                "NIST finalized FIPS 204 as a post-quantum cryptography standard based on ML-DSA."
                    .to_string(),
        },
    ];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        2,
        &selected_urls,
        &source_hints,
        None,
    );

    assert!(!observation.identifier_evidence_required);
    assert!(observation.identifier_coverage_floor_met);
    assert_eq!(observation.distinct_domains, 1);
    assert!(!observation.quality_floor_met);
}

#[test]
fn document_briefing_quality_observation_rejects_duplicate_ir_authority_family_fill() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let selected_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process."
                    .to_string(),
        },
    ];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        2,
        &selected_urls,
        &source_hints,
        None,
    );

    assert!(observation.identifier_evidence_required);
    assert_eq!(observation.compatible_sources, 2);
    assert_eq!(observation.required_identifier_group_floor, 1);
    assert_eq!(observation.required_identifier_label_coverage, 1);
    assert!(observation.identifier_coverage_floor_met);
    assert!(!observation.quality_floor_met);
    assert!(observation.missing_identifier_urls.is_empty());
}

#[test]
fn document_briefing_quality_observation_rejects_empty_snippet_duplicate_authority_family_fill() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let selected_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt: "".to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt: "".to_string(),
        },
    ];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        2,
        &selected_urls,
        &source_hints,
        None,
    );

    assert_eq!(observation.compatible_sources, 2);
    assert_eq!(observation.required_identifier_group_floor, 1);
    assert!(observation.identifier_coverage_floor_met);
    assert!(!observation.quality_floor_met);
}

#[test]
fn document_briefing_quality_observation_accepts_grounded_external_pdf_support_with_authority_pairing(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let selected_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf"
            .to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 Update 1 tracks the current post-quantum cryptography standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some("91% of organizations".to_string()),
            excerpt:
                "Industry readiness report for quantum-safe migration and deployment planning."
                    .to_string(),
        },
    ];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        2,
        &selected_urls,
        &source_hints,
        None,
    );

    assert_eq!(observation.total_sources, 2);
    assert_eq!(observation.compatible_sources, 2);
    assert_eq!(observation.distinct_domains, 2);
    assert!(observation.quality_floor_met);
}

#[test]
fn current_office_holder_quality_observation_accepts_identity_grounded_current_holder_surface() {
    let query = "Who is the current Secretary-General of the UN?";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let selected_urls = vec!["https://ask.un.org/faq/14625".to_string()];
    let source_hints = vec![PendingSearchReadSummary {
        url: selected_urls[0].clone(),
        title: Some(
            "Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                .to_string(),
        ),
        excerpt:
            "António Guterres is the current Secretary-General of the United Nations."
                .to_string(),
    }];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        1,
        &selected_urls,
        &source_hints,
        None,
    );

    assert_eq!(observation.total_sources, 1);
    assert_eq!(observation.compatible_sources, 1, "{observation:#?}");
    assert!(observation.quality_floor_met, "{observation:#?}");
    assert!(observation.identifier_coverage_floor_met, "{observation:#?}");
}

#[test]
fn local_business_quality_observation_requires_entity_anchor_compatible_sources() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let selected_urls = vec![
        "https://www.restaurantji.com/sc/anderson/chick-fil-a-/".to_string(),
        "https://www.restaurantji.com/sc/anderson/arnolds-famous-homemade-hamburgers-/".to_string(),
        "https://www.restaurantji.com/sc/anderson/arbys-2/".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "Chick-fil-A, Anderson - Menu, Reviews (189), Photos (44) - Restaurantji"
                    .to_string(),
            ),
            excerpt:
                "Fast-food restaurant in Anderson, SC serving chicken sandwiches, nuggets and fries."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some(
                "Arnold's Famous Homemade Hamburgers, Anderson - Menu, Reviews (214), Photos (38) - Restaurantji"
                    .to_string(),
            ),
            excerpt:
                "American restaurant in Anderson, SC serving burgers, onion rings and shakes."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some(
                "Arby's, Anderson - Menu, Reviews (145), Photos (21) - Restaurantji".to_string(),
            ),
            excerpt:
                "Fast-food restaurant in Anderson, SC serving roast beef sandwiches and curly fries."
                    .to_string(),
        },
    ];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        3,
        &selected_urls,
        &source_hints,
        Some("Anderson, SC"),
    );

    assert!(observation.entity_anchor_required);
    assert_eq!(observation.entity_anchor_compatible_sources, 0);
    assert!(!observation.entity_anchor_floor_met);
    assert!(!observation.quality_floor_met);
    assert!(observation.entity_anchor_source_urls.is_empty());
    assert_eq!(observation.entity_anchor_mismatched_urls, selected_urls);
}

#[test]
fn local_business_quality_observation_accepts_entity_anchor_compatible_sources() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
        .expect("retrieval contract");
    let selected_urls = vec![
        "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/".to_string(),
        "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/".to_string(),
        "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-/".to_string(),
    ];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: selected_urls[0].clone(),
            title: Some(
                "Brothers Italian Cuisine, Anderson - Menu, Reviews (226), Photos (25) - Restaurantji"
                    .to_string(),
            ),
            excerpt: "Italian restaurant in Anderson, SC serving pizza, pasta and subs.".to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[1].clone(),
            title: Some(
                "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                    .to_string(),
            ),
            excerpt:
                "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: selected_urls[2].clone(),
            title: Some(
                "Dolce Vita Italian Bistro, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                    .to_string(),
            ),
            excerpt:
                "Italian bistro in Anderson, SC with pizza, pasta, calzones and dessert."
                    .to_string(),
        },
    ];

    let observation = selected_source_quality_observation_with_contract_and_locality_hint(
        Some(&contract),
        query,
        3,
        &selected_urls,
        &source_hints,
        Some("Anderson, SC"),
    );

    assert!(observation.entity_anchor_required);
    assert_eq!(observation.entity_anchor_compatible_sources, 3);
    assert!(observation.entity_anchor_floor_met);
    assert!(observation.quality_floor_met);
    assert_eq!(observation.entity_anchor_source_urls, selected_urls);
    assert!(observation.entity_anchor_mismatched_urls.is_empty());
}
