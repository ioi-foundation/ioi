#[test]
fn grounded_probe_query_availability_detects_non_recoverable_latest_nist_answer_loop() {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: Vec::new(),
        candidate_source_hints: Vec::new(),
        attempted_urls: vec![
            "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: Vec::new(),
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt:
                    "NIST directs organizations to migrate to post-quantum encryption standards now."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    assert!(!grounded_probe_query_available(&pending, None));
    assert_eq!(
        web_pipeline_completion_reason(&pending, 1_773_117_280_000),
        Some(WebPipelineCompletionReason::ExhaustedCandidates)
    );
}

#[test]
fn source_cluster_contract_ready_terminalizes_latest_nist_answer_when_grounded_sources_are_merged()
{
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some(
                    "Federal Information Processing Standard (FIPS) 204".to_string(),
                ),
                excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                    .to_string(),
            },
        ],
        attempted_urls: vec![
            "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: vec![
            "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans"
                .to_string(),
        ],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some(
                    "Federal Information Processing Standard (FIPS) 204".to_string(),
                ),
                excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                    .to_string(),
            },
        ],
        min_sources: 3,
    };

    let summary = "# NIST post-quantum cryptography standards\n\nSummary: NIST's post-quantum cryptography standards baseline is anchored by the finalized FIPS 203, FIPS 204, and FIPS 205 documents, with IBM providing additional ecosystem context.\n\nEvidence:\n- NIST released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum encryption standards.\n- The CSRC FIPS 204 publication identifies ML-DSA, and IBM confirms the finalized standards set.\n\nSources:\n- [NIST Releases First 3 Finalized Post-Quantum Encryption Standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)\n- [Federal Information Processing Standard (FIPS) 204](https://csrc.nist.gov/pubs/fips/204/final)\n- [IBM Research: NIST's post-quantum cryptography standards are here](https://research.ibm.com/blog/nist-pqc-standards)";
    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        &summary,
    );
    assert!(facts
        .answer_required_sections
        .iter()
        .any(|section| section == "what_happened"));
    assert!(facts
        .answer_required_sections
        .iter()
        .any(|section| section == "key_evidence"));
    assert_eq!(facts.answer_layout_profile, "document_report");
    assert_eq!(facts.answer_legacy_source_cluster_header_count, 0);
    assert!(facts.answer_legacy_source_cluster_headers_absent);
    assert_eq!(facts.answer_comparison_label_count, 0);
    assert!(facts.answer_comparison_absent);
    assert!(facts.answer_query_grounding_floor_met);
    assert!(facts.evidence_standard_identifier_floor_met);
    assert!(facts.evidence_authority_standard_identifier_floor_met);
    assert!(facts.evidence_inventory_floor_met);
    assert!(facts.answer_evidence_block_floor_met);
    assert!(!summary.contains("Run date (UTC):"));
    assert!(!summary.contains("Run timestamp (UTC):"));
    assert!(!summary.contains("Overall confidence:"));
    assert!(source_cluster_completion_contract_ready(&pending, 3));
    assert_eq!(
        web_pipeline_completion_reason(&pending, 1_773_117_280_000),
        Some(WebPipelineCompletionReason::MinSourcesReached)
    );
}

#[test]
fn source_cluster_contract_ready_requires_primary_authority_source_when_available_for_document_report(
) {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![
            "https://www.nist.gov/pqc".to_string(),
            "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
            },
        ],
        attempted_urls: vec![
            "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.digicert.com/blog/nist-standards-for-quantum-safe-cryptography"
                    .to_string(),
                title: Some("NIST standards for quantum-safe cryptography".to_string()),
                excerpt: "DigiCert explains the latest NIST standards for quantum-safe cryptography.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let facts =
        final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert_eq!(facts.available_primary_authority_source_count, 1);
    assert_eq!(facts.selected_primary_authority_source_count, 0);
    assert!(!facts.evidence_primary_authority_source_floor_met);
    assert!(!source_cluster_completion_contract_ready(&pending, 1));
}

#[test]
fn source_cluster_contract_ready_prefers_ir_evidence_authority_citations_over_generic_nist_policy_pages(
) {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_775_094_450_000,
        deadline_ms: 1_775_094_570_000,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "NIST's current authoritative publication set for the post-quantum cryptography standardization process includes IR 8413."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the authoritative NIST status report for the post-quantum cryptography standardization process."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/no-fear-act-policy".to_string(),
                title: Some("No Fear Act Policy | NIST".to_string()),
                excerpt:
                    "NIST publishes its No Fear Act policy information for general agency compliance."
                        .to_string(),
            },
        ],
        min_sources: 2,
    };

    let summary = "# NIST IR 8413 authority check\n\nSummary: The useful current authoritative publications are the two IR 8413 CSRC entries; the general NIST policy page is unrelated to the post-quantum standards question.\n\nEvidence:\n- Both selected CSRC pages identify IR 8413 as the authoritative NIST status report for the post-quantum cryptography standardization process.\n- The NIST No Fear Act page does not address the post-quantum cryptography standards question.\n\nSources:\n- [IR 8413 update](https://csrc.nist.gov/pubs/ir/8413/upd1/final)\n- [IR 8413 final](https://csrc.nist.gov/pubs/ir/8413/final)";
    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        &summary,
    );

    assert!(summary.contains("current authoritative publications"));
    assert!(summary.contains("https://csrc.nist.gov/pubs/ir/8413/upd1/final"));
    assert!(summary.contains("https://csrc.nist.gov/pubs/ir/8413/final"));
    assert!(!summary.contains("https://www.nist.gov/no-fear-act-policy"));
    assert!(facts.evidence_inventory_floor_met);
    assert!(!facts.evidence_selected_source_quality_floor_met);
    assert!(facts.evidence_selected_source_identifier_coverage_floor_met);
    assert!(facts
        .selected_source_urls
        .iter()
        .any(|url| { url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final") }));
    assert!(facts
        .selected_source_urls
        .iter()
        .any(|url| { url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/final") }));
    assert!(!facts
        .selected_source_urls
        .iter()
        .any(|url| { url.eq_ignore_ascii_case("https://www.nist.gov/no-fear-act-policy") }));
    assert!(!final_web_completion_contract_ready(&facts));
}

#[test]
fn source_cluster_contract_ready_requires_menu_surface_sources_for_restaurant_menu_comparison() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract"),
        ),
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Brothers Italian Cuisine",
                    query,
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Coach House Restaurant",
                    query,
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Dolce Vita Italian Bistro and Pizzeria",
                    query,
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
                excerpt:
                    "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/"
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

    let facts =
        final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

    assert!(facts.local_business_menu_surface_required);
    assert!(facts.local_business_menu_surface_source_urls.is_empty());
    assert!(!facts.local_business_menu_surface_floor_met);
    assert!(!source_cluster_completion_contract_ready(&pending, 3));
    assert!(!final_web_completion_contract_ready(&facts));
}

#[test]
fn source_cluster_contract_ready_accepts_menu_surface_sources_for_restaurant_menu_comparison() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract"),
        ),
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Brothers Italian Cuisine",
                    query,
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Coach House Restaurant",
                    query,
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Dolce Vita Italian Bistro and Pizzeria",
                    query,
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                    .to_string(),
                title: Some("Menu".to_string()),
                excerpt:
                    "Customers' favorites include Brothers Special Shrimp Pasta, Chef Salad, Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone. Menu photo gallery available with 6 images."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                    .to_string(),
                title: Some("Menu".to_string()),
                excerpt:
                    "Customers' favorites include Assorted Home Made Cakes, Chicken and Dumplings, Chicken Fried Steak, Baked Greek Chicken, and Roast Beef Sandwich. Menu photo gallery available with 19 images."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/menu/"
                    .to_string(),
                title: Some("Menu".to_string()),
                excerpt:
                    "Customers' favorites include Margherita Pizza, Baked Ziti, Chicken Alfredo, Calzone, and Cannoli. Menu photo gallery available with 7 images."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    let facts =
        final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

    assert!(facts.local_business_menu_surface_required);
    assert_eq!(facts.local_business_menu_surface_source_urls.len(), 3);
    assert!(facts.local_business_menu_surface_floor_met);
    assert_eq!(facts.local_business_menu_inventory_source_urls.len(), 3);
    assert!(facts.local_business_menu_inventory_total_item_count >= 6);
    assert!(facts.local_business_menu_inventory_floor_met);
    assert!(source_cluster_completion_contract_ready(&pending, 3));
    assert!(final_web_completion_contract_ready(&facts));
}

#[test]
fn source_cluster_contract_ready_requires_menu_inventory_for_restaurant_menu_comparison() {
    let query =
        "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
    let pending = PendingSearchCompletion {
        query: query.to_string(),
        query_contract: query.to_string(),
        retrieval_contract: Some(
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract"),
        ),
        url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Brothers Italian Cuisine",
                    query,
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Coach House Restaurant",
                    query,
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Dolce Vita Italian Bistro and Pizzeria",
                    query,
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                    .to_string(),
                title: Some("Menu".to_string()),
                excerpt:
                    "View the menu, hours, phone number, address and map for Brothers Italian Cuisine."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                    .to_string(),
                title: Some("Menu".to_string()),
                excerpt:
                    "View the menu, hours, phone number, address and map for Coach House Restaurant."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/menu/"
                    .to_string(),
                title: Some("Menu".to_string()),
                excerpt:
                    "View the menu, hours, phone number, address and map for Dolce Vita Italian Bistro and Pizzeria."
                        .to_string(),
            },
        ],
        min_sources: 3,
    };

    let facts =
        final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

    assert!(facts.local_business_menu_surface_required);
    assert_eq!(facts.local_business_menu_surface_source_urls.len(), 3);
    assert!(facts.local_business_menu_surface_floor_met);
    assert!(facts.local_business_menu_inventory_source_urls.is_empty());
    assert_eq!(facts.local_business_menu_inventory_total_item_count, 0);
    assert!(!facts.local_business_menu_inventory_floor_met);
    assert!(!source_cluster_completion_contract_ready(&pending, 3));
    assert!(!final_web_completion_contract_ready(&facts));
}

#[test]
fn menu_inventory_parser_accepts_canonical_inventory_intro() {
    let items = local_business_menu_inventory_items_from_excerpt(
        "Item inventory includes Organic Smoked Ham Hero Sandwich, Meatball Hero Sandwich, Gourmet Chicken Hero Sandwich, and Philly Steak & Cheese Hero Sandwich.",
    );

    assert_eq!(
        items,
        vec![
            "Organic Smoked Ham Hero Sandwich".to_string(),
            "Meatball Hero Sandwich".to_string(),
            "Gourmet Chicken Hero Sandwich".to_string(),
            "Philly Steak & Cheese Hero Sandwich".to_string(),
        ]
    );
}

#[test]
fn source_cluster_contract_ready_requires_authority_identifier_coverage_for_document_report() {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
            "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        ],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                        .to_string(),
                ),
                excerpt: "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum cryptography standards."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "IBM summarized FIPS 203, FIPS 204, and FIPS 205 after NIST released the finalized standards."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some(
                    "Federal Information Processing Standard (FIPS) 204".to_string(),
                ),
                excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                    .to_string(),
            },
        ],
        min_sources: 3,
    };

    let facts =
        final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert_eq!(facts.answer_layout_profile, "document_report");
    assert!(facts.evidence_selected_source_quality_floor_met);
    assert!(!facts.evidence_authority_standard_identifier_floor_met);
    assert!(!source_cluster_completion_contract_ready(&pending, 1));
}

#[test]
fn source_cluster_contract_ready_requires_primary_authority_source_when_authority_read_was_attempted(
) {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.nist.gov/pqc".to_string(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
        }],
        attempted_urls: vec![
            "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            "https://www.nist.gov/pqc".to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://cyberscoop.com/why-federal-it-leaders-must-act-now-to-deliver-nists-post-quantum-cryptography-transition-op-ed/".to_string(),
                title: Some(
                    "Why federal IT leaders must act now to deliver NIST’s post-quantum cryptography transition"
                        .to_string(),
                ),
                excerpt: "CyberScoop covers federal post-quantum cryptography transition planning.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.cybersecuritydive.com/news/nist-post-quantum-cryptography-guidance-mapping/760638/".to_string(),
                title: Some(
                    "NIST explains how post-quantum cryptography push overlaps with existing security guidance"
                        .to_string(),
                ),
                excerpt: "Cybersecurity Dive covers NIST post-quantum cryptography guidance mapping.".to_string(),
            },
        ],
        min_sources: 2,
    };

    let facts =
        final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
    assert_eq!(facts.available_primary_authority_source_count, 0);
    assert_eq!(facts.attempted_primary_authority_source_count, 1);
    assert_eq!(facts.selected_primary_authority_source_count, 0);
    assert!(!facts.evidence_primary_authority_source_floor_met);
    assert!(!source_cluster_completion_contract_ready(&pending, 1));
}

#[test]
fn rendered_document_report_reserves_slot_for_independent_corroboration() {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards&format=rss"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![
            "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption"
                .to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                .to_string(),
        ],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                title: Some(
                    "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                        .to_string(),
                ),
                excerpt: "NIST selected HQC in 2025 after finalizing FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                        .to_string(),
                ),
                excerpt: "NIST finalized FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                excerpt: "Independent analysis summarized the finalized standards set."
                    .to_string(),
            },
        ],
        min_sources: 2,
    };

    let summary = "# NIST post-quantum cryptography standards\n\nSummary: As of 2026-03-10, retrieved authoritative sources identify the current standards as FIPS 203, FIPS 204, and FIPS 205.\n\nEvidence:\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST, NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n- Independent analysis corroborated the finalized standards set.\n\nCitations:\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | 2026-03-10T23:36:24Z | retrieved_utc\n- Diving Into NIST’s New Post-Quantum Standards | https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/ | 2026-03-10T23:36:24Z | retrieved_utc\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T23:36:24Z\nOverall confidence: medium";

    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        summary,
    );

    assert_eq!(facts.available_primary_authority_source_count, 2);
    assert_eq!(facts.answer_required_primary_authority_source_count, 1);
    assert_eq!(facts.selected_primary_authority_source_count, 1);
    assert!(facts.evidence_primary_authority_source_floor_met);
}

#[test]
fn document_report_min_sources_completion_allows_stale_queued_reads_without_viable_followup() {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![
            "https://www.nist.gov/pqc".to_string(),
            "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
            },
        ],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
            },
        ],
        min_sources: 2,
    };

    assert!(web_pipeline_completion_terminalization_allowed(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        1,
    ));
    assert!(web_pipeline_completion_terminalization_allowed(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        0,
    ));
}

#[test]
fn document_report_min_sources_completion_allows_model_handoff_with_queued_followup_read() {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![
            "https://www.nist.gov/pqc".to_string(),
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some("FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard | CSRC".to_string()),
                excerpt: "NIST finalized FIPS 203 as one of the first post-quantum cryptography standards.".to_string(),
            },
        ],
        attempted_urls: vec!["https://www.nist.gov/pqc".to_string()],
        blocked_urls: vec![],
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://www.nist.gov/pqc".to_string(),
            title: Some("Post-quantum cryptography | NIST".to_string()),
            excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
        }],
        min_sources: 1,
    };

    assert!(web_pipeline_completion_terminalization_allowed(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        1,
    ));
}

#[test]
fn rendered_summary_shape_facts_fail_for_source_collection_output_on_document_report_queries() {
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract:
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                .to_string(),
        retrieval_contract: Some(nist_answer_contract()),
        url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
            .to_string(),
        started_step: 1,
        started_at_ms: 1_773_117_248_754,
        deadline_ms: 1_773_117_308_754,
        candidate_urls: vec![],
        candidate_source_hints: vec![],
        attempted_urls: vec![],
        blocked_urls: vec![],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt:
                    "NIST says now is the time to migrate to post-quantum encryption standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                title: Some(
                    "NIST’s post-quantum cryptography standards are here - IBM Research"
                        .to_string(),
                ),
                excerpt: "IBM summarized FIPS 203, FIPS 204, and FIPS 205.".to_string(),
            },
        ],
        min_sources: 2,
    };
    let bad_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.";
    let facts = final_web_completion_facts_with_rendered_summary(
        &pending,
        WebPipelineCompletionReason::MinSourcesReached,
        bad_summary,
    );

    assert!(!facts.answer_document_layout_met);
    assert!(facts.answer_query_layout_expected);
    assert_eq!(facts.answer_rendered_layout_profile, "source_collection");
    assert!(!facts.answer_render_heading_floor_met);
    assert!(!facts.answer_rendered_required_section_label_floor_met);
    assert_eq!(facts.answer_legacy_source_cluster_header_count, 1);
    assert!(!facts.answer_legacy_source_cluster_headers_absent);
    assert_eq!(facts.answer_comparison_label_count, 1);
    assert!(!facts.answer_comparison_absent);
    assert!(!facts.answer_required_section_floor_met);
    assert!(!facts.answer_query_grounding_floor_met);
    assert!(!facts.evidence_standard_identifier_floor_met);
    assert!(!facts.answer_narrative_aggregation_floor_met);
    assert!(!facts.trace_temporal_anchor_floor_met);
    assert!(!facts.trace_metadata_floor_met);
    assert!(!final_web_completion_contract_ready(&facts));
}
