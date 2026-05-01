use super::*;
use crate::agentic::runtime::service::queue::support::PreReadCandidatePlan;

fn research_query_contract() -> String {
    "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
        .to_string()
}

fn research_retrieval_contract() -> ioi_types::app::agentic::WebRetrievalContract {
    crate::agentic::web::derive_web_retrieval_contract(&research_query_contract(), None)
        .expect("retrieval contract")
}

fn restaurant_query_contract() -> String {
    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus."
        .to_string()
}

fn restaurant_retrieval_contract() -> ioi_types::app::agentic::WebRetrievalContract {
    crate::agentic::web::derive_web_retrieval_contract(&restaurant_query_contract(), None)
        .expect("retrieval contract")
}

fn restaurant_source_hints() -> Vec<PendingSearchReadSummary> {
    vec![
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
    ]
}

#[test]
fn authority_hint_read_recovery_site_terms_add_publication_scope_for_csrc_ir_url() {
    let terms = authority_hint_read_recovery_site_terms(&[String::from(
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
    )]);

    assert!(
        terms
            .iter()
            .any(|term| term.eq_ignore_ascii_case("site:csrc.nist.gov/pubs")),
        "terms={terms:?}"
    );
}

#[test]
fn append_missing_query_terms_appends_publication_scope_once() {
    let query =
        "nist post quantum cryptography standards \"nist post quantum cryptography\" \"observed now\"";
    let next = append_missing_query_terms(
        query,
        &[
            String::from("site:csrc.nist.gov/pubs"),
            String::from("site:csrc.nist.gov/pubs"),
        ],
    );

    assert!(next.contains("site:csrc.nist.gov/pubs"), "next={next}");
    assert_eq!(
        next.matches("site:csrc.nist.gov/pubs").count(),
        1,
        "next={next}"
    );
}

#[test]
fn deterministic_local_business_direct_selection_requires_distinct_entities() {
    let query_contract = restaurant_query_contract();
    let retrieval_contract = restaurant_retrieval_contract();
    let source_hints = restaurant_source_hints();
    let candidate_urls = source_hints
        .iter()
        .map(|hint| hint.url.clone())
        .collect::<Vec<_>>();

    let selected = deterministic_local_business_direct_detail_urls(
        &retrieval_contract,
        &query_contract,
        3,
        &candidate_urls,
        &source_hints,
        Some("Anderson, SC"),
        3,
    );

    assert!(selected.is_empty(), "{selected:?}");
}

#[test]
fn deterministic_local_business_seed_selection_finds_listing_surface() {
    let query_contract = restaurant_query_contract();
    let retrieval_contract = restaurant_retrieval_contract();
    let source_hints = restaurant_source_hints();

    let seed_url = deterministic_local_business_discovery_seed_url(
        &retrieval_contract,
        &query_contract,
        3,
        &vec![
            WebSource {
                source_id: "1".to_string(),
                rank: Some(1),
                url: "https://www.yelp.com/biz/dolce-vita-italian-bistro-and-pizzeria-anderson"
                    .to_string(),
                title: Some(
                    "Dolce Vita Italian Bistro and Pizzeria - Anderson, SC - Yelp"
                        .to_string(),
                ),
                snippet: Some(
                    "Italian restaurant in Anderson, SC with pasta, pizza, and baked dishes."
                        .to_string(),
                ),
                domain: Some("www.yelp.com".to_string()),
            },
            WebSource {
                source_id: "2".to_string(),
                rank: Some(2),
                url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html".to_string(),
                title: Some("THE 10 BEST Italian Restaurants in Anderson (Updated 2026) - Tripadvisor".to_string()),
                snippet: Some(
                    "Best Italian Restaurants in Anderson, South Carolina: find reviews for Dolce Vita, The Red Tomato, and Brothers Italian Cuisine."
                        .to_string(),
                ),
                domain: Some("www.tripadvisor.com".to_string()),
            },
        ],
        &[],
        &source_hints,
        Some("Anderson, SC"),
    );

    assert_eq!(
        seed_url.as_deref(),
        Some("https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html")
    );
}

#[test]
fn briefing_grounded_recovery_does_not_block_when_selection_ready() {
    let query_contract = research_query_contract();
    let retrieval_contract = research_retrieval_contract();
    let plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://csrc.nist.gov/Projects/post-quantum-cryptography/workshops-and-timeline"
                .to_string(),
            "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf"
                .to_string(),
        ],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };

    assert!(!briefing_grounded_recovery_required(
        &query_contract,
        &retrieval_contract,
        &plan,
        2,
        true,
    ));
}

#[test]
fn briefing_grounded_recovery_still_requires_probe_when_selection_sparse() {
    let query_contract = research_query_contract();
    let retrieval_contract = research_retrieval_contract();
    let plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf"
                .to_string(),
        ],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };

    assert!(briefing_grounded_recovery_required(
        &query_contract,
        &retrieval_contract,
        &plan,
        2,
        false,
    ));
}

#[test]
fn briefing_grounded_recovery_attempt_marker_prevents_repeat_queue() {
    let recovery_query =
        "nist post quantum cryptography standards web UTC timestamp site:nist.gov";
    let mut pending = PendingSearchCompletion::default();

    assert!(!briefing_grounded_recovery_attempted(
        Some(&pending),
        recovery_query,
    ));

    mark_briefing_grounded_recovery_attempt(&mut pending, recovery_query);

    assert!(briefing_grounded_recovery_attempted(
        Some(&pending),
        recovery_query,
    ));
    assert_eq!(pending.attempted_urls.len(), 1);

    mark_briefing_grounded_recovery_attempt(&mut pending, recovery_query);

    assert_eq!(pending.attempted_urls.len(), 1);
}

#[test]
fn semantic_alignment_recovery_query_escalates_away_from_off_topic_authority_neighbor_host() {
    let query_contract = research_query_contract();
    let retrieval_contract = research_retrieval_contract();
    let prior_query =
        "nist post quantum cryptography standards web UTC timestamp site:nist.gov \"nist post quantum cryptography\"";
    let candidate_hints = vec![PendingSearchReadSummary {
        url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
            .to_string(),
        title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
        excerpt:
            "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                .to_string(),
    }];

    let recovery_query = semantic_alignment_recovery_query(
        &query_contract,
        prior_query,
        &retrieval_contract,
        2,
        &candidate_hints,
        None,
    );

    assert_ne!(recovery_query, prior_query);
    assert!(
        recovery_query
            .split_whitespace()
            .any(|term| term.eq_ignore_ascii_case("site:nist.gov")),
        "recovery_query={recovery_query}"
    );
    assert!(
        recovery_query
            .split_whitespace()
            .any(|term| term.eq_ignore_ascii_case("-site:ibm.com")),
        "recovery_query={recovery_query}"
    );
}

#[test]
fn merge_deterministic_plan_with_pending_inventory_reuses_prior_authority_candidates_when_current_turn_is_sparse(
) {
    let query_contract = research_query_contract();
    let retrieval_contract = research_retrieval_contract();
    let pending = PendingSearchCompletion {
        query: query_contract.clone(),
        query_contract: query_contract.clone(),
        retrieval_contract: Some(retrieval_contract.clone()),
        candidate_urls: vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
                    .to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
        ],
        min_sources: 2,
        ..PendingSearchCompletion::default()
    };
    let sparse_plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
            excerpt:
                "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                    .to_string(),
        }],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };
    let mut checks = Vec::new();

    let merged = merge_deterministic_plan_with_pending_inventory(
        &retrieval_contract,
        &query_contract,
        2,
        None,
        Some(&pending),
        sparse_plan,
        &mut checks,
    );

    assert_eq!(
        merged.candidate_urls.len(),
        2,
        "{:?}",
        merged.candidate_urls
    );
    assert!(merged
        .candidate_urls
        .iter()
        .any(|url| url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")));
    assert!(merged.candidate_urls.iter().any(|url| {
        url.eq_ignore_ascii_case(
            "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf",
        )
    }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_pre_read_pending_inventory_reused=true" }));
}

#[test]
fn merge_deterministic_plan_with_pending_inventory_does_not_reuse_on_query_contract_mismatch() {
    let query_contract = research_query_contract();
    let retrieval_contract = research_retrieval_contract();
    let pending = PendingSearchCompletion {
        query_contract: "Research the latest OpenAI API pricing updates and write me a memo."
            .to_string(),
        candidate_urls: vec![
            "https://openai.com/api/pricing".to_string(),
            "https://platform.openai.com/docs/pricing".to_string(),
        ],
        min_sources: 2,
        ..PendingSearchCompletion::default()
    };
    let sparse_plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
        ],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };
    let mut checks = Vec::new();

    let merged = merge_deterministic_plan_with_pending_inventory(
        &retrieval_contract,
        &query_contract,
        2,
        None,
        Some(&pending),
        sparse_plan.clone(),
        &mut checks,
    );

    assert_eq!(merged.candidate_urls, sparse_plan.candidate_urls);
    assert!(checks
        .iter()
        .any(|check| { check == "web_pre_read_pending_inventory_reused=false" }));
}

#[test]
fn merge_deterministic_plan_with_pending_inventory_reconstructs_candidate_urls_from_pending_hints(
) {
    let query_contract = research_query_contract();
    let retrieval_contract = research_retrieval_contract();
    let pending = PendingSearchCompletion {
        query: query_contract.clone(),
        query_contract: query_contract.clone(),
        retrieval_contract: Some(retrieval_contract.clone()),
        candidate_urls: Vec::new(),
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
                    .to_string(),
                title: Some(
                    "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                        .to_string(),
                ),
                excerpt:
                    "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
        ],
        min_sources: 2,
        ..PendingSearchCompletion::default()
    };
    let sparse_plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
            excerpt:
                "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                    .to_string(),
        }],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };
    let mut checks = Vec::new();

    let merged = merge_deterministic_plan_with_pending_inventory(
        &retrieval_contract,
        &query_contract,
        2,
        None,
        Some(&pending),
        sparse_plan,
        &mut checks,
    );

    assert_eq!(
        merged.candidate_urls.len(),
        2,
        "{:?}",
        merged.candidate_urls
    );
    assert!(merged
        .candidate_urls
        .iter()
        .any(|url| url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")));
    assert!(merged.candidate_urls.iter().any(|url| {
        url.eq_ignore_ascii_case(
            "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf",
        )
    }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_pre_read_pending_inventory_reused=true" }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_pre_read_pending_inventory_candidate_urls=2" }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_pre_read_pending_inventory_raw_candidate_urls=0" }));
}

#[test]
fn merge_deterministic_plan_with_pending_inventory_preserves_distinct_official_support_from_run_shaped_research_inventory(
) {
    let query_contract = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.".to_string();
    let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(
        &query_contract,
        Some(&query_contract),
    )
    .unwrap();
    let pending = PendingSearchCompletion {
        query: "nist post quantum cryptography standards".to_string(),
        query_contract: query_contract.clone(),
        retrieval_contract: Some(retrieval_contract.clone()),
        candidate_urls: vec![
            "https://csrc.nist.gov/pubs/ir/8547/ipd".to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
            "https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/news".to_string(),
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://csrc.nist.gov/pubs/ir/8545/final".to_string(),
            "https://csrc.nist.gov/projects/post-quantum-cryptography".to_string(),
            "https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/publications".to_string(),
            "https://csrc.nist.gov/Projects/Cryptographic-Standards-and-Guidelines".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
            "https://www.nist.gov/news-events/news/2026/03/nist-researchers-develop-photonic-chip-packaging-can-withstand-extreme".to_string(),
            "https://csrc.nist.gov/".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8547/ipd".to_string(),
                title: Some(
                    "IR 8547 (Initial Public Draft), Transition to Post-Quantum Cryptography Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST draft guidance on transitioning to the latest post-quantum cryptography standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
                title: Some("Post-Quantum Cryptography Standardization | CSRC".to_string()),
                excerpt:
                    "Current CSRC project page for the latest NIST post-quantum cryptography standardization updates."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
                title: Some("Post-Quantum Cryptography FIPS Approved | CSRC".to_string()),
                excerpt:
                    "CSRC announced approval of the post-quantum cryptography FIPS standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST released the first three finalized post-quantum encryption standards and urged administrators to begin transitioning."
                        .to_string(),
            },
        ],
        successful_reads: vec![
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                        .to_string(),
            },
        ],
        min_sources: 2,
        ..PendingSearchCompletion::default()
    };
    let sparse_plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
            title: Some(
                "Sponsored: Building organizational readiness for post-quantum cryptography"
                    .to_string(),
            ),
            excerpt:
                "Sponsored briefing on organizational readiness for post-quantum cryptography."
                    .to_string(),
        }],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };
    let mut checks = Vec::new();

    let merged = merge_deterministic_plan_with_pending_inventory(
        &retrieval_contract,
        &query_contract,
        2,
        None,
        Some(&pending),
        sparse_plan,
        &mut checks,
    );

    assert!(
        merged.candidate_urls.len() >= 2,
        "{:?}",
        merged.candidate_urls
    );
    assert!(
        merged.candidate_urls.iter().any(|url| {
            url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")
        }),
        "{:?}",
        merged.candidate_urls
    );
    assert!(
        merged.candidate_urls.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            )
        }),
        "{:?}",
        merged.candidate_urls
    );
    assert!(
        checks
            .iter()
            .any(|check| { check == "web_pre_read_pending_inventory_reused=true" }),
        "{checks:?}"
    );
}

#[test]
fn pre_read_selection_sources_merge_pending_authority_with_live_support_artifact() {
    let query_contract = research_query_contract();
    let retrieval_contract = research_retrieval_contract();
    let planning_bundle = WebEvidenceBundle {
        schema_version: 1,
        retrieved_at_ms: 0,
        tool: "web__search".to_string(),
        backend: "test".to_string(),
        query: Some(query_contract.clone()),
        url: Some("https://example.test/search".to_string()),
        sources: vec![
            WebSource {
                source_id: crate::agentic::web::source_id_for_url(
                    "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/",
                ),
                rank: Some(1),
                url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                title: Some(
                    "Sponsored: Building organizational readiness for post-quantum cryptography"
                        .to_string(),
                ),
                snippet: Some(
                    "Sponsored briefing on organizational readiness for post-quantum cryptography."
                        .to_string(),
                ),
                domain: Some("www.ciodive.com".to_string()),
            },
            WebSource {
                source_id: crate::agentic::web::source_id_for_url(
                    "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
                ),
                rank: Some(2),
                url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
                title: Some("State of PQC Readiness 2025".to_string()),
                snippet: Some(
                    "Independent November 2025 report on post-quantum cryptography readiness after NIST finalized its first post-quantum standards."
                        .to_string(),
                ),
                domain: Some("trustedcomputinggroup.org".to_string()),
            },
        ],
        source_observations: vec![ioi_types::app::agentic::WebSourceObservation {
            url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
            affordances: vec![
                ioi_types::app::agentic::WebRetrievalAffordance::DetailDocument,
                ioi_types::app::agentic::WebRetrievalAffordance::CanonicalLinkOut,
                ioi_types::app::agentic::WebRetrievalAffordance::LinkCollection,
            ],
            expansion_affordances: vec![
                ioi_types::app::agentic::WebSourceExpansionAffordance::ChildLinkCollection,
            ],
        }],
        documents: Vec::new(),
        provider_candidates: Vec::new(),
        retrieval_contract: Some(retrieval_contract),
    };
    let prioritized_hints = ordered_source_hints_with_selected_urls_first(
        &["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
        &[
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                title: Some(
                    "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                        .to_string(),
                ),
                excerpt:
                    "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
                title: Some("State of PQC Readiness 2025".to_string()),
                excerpt:
                    "Independent November 2025 report on post-quantum cryptography readiness after NIST finalized its first post-quantum standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
                title: Some(
                    "Sponsored: Building organizational readiness for post-quantum cryptography"
                        .to_string(),
                ),
                excerpt:
                    "Sponsored briefing on organizational readiness for post-quantum cryptography."
                        .to_string(),
            },
        ],
    );

    let payload_sources =
        pre_read_selection_sources_from_planning_context(&planning_bundle, &prioritized_hints);
    let payload_observations = pre_read_selection_source_observations_from_planning_context(
        &planning_bundle,
        &payload_sources,
    );

    assert_eq!(
        payload_sources.first().map(|source| source.url.as_str()),
        Some("https://csrc.nist.gov/pubs/ir/8413/upd1/final")
    );
    assert!(payload_sources.iter().any(|source| {
        source.url.eq_ignore_ascii_case(
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
        )
    }));
    assert!(payload_sources.iter().any(|source| {
        source.url.eq_ignore_ascii_case(
            "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/",
        )
    }));
    assert_eq!(payload_observations.len(), 1);
    assert_eq!(
        payload_observations.first().map(|observation| observation.url.as_str()),
        Some(
            "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/"
        )
    );
}

#[test]
fn seed_pending_inventory_from_pre_read_payload_hints_preserves_expanded_support_candidates() {
    let mut pending = PendingSearchCompletion {
        query: research_query_contract(),
        query_contract: research_query_contract(),
        retrieval_contract: Some(research_retrieval_contract()),
        candidate_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        min_sources: 2,
        ..PendingSearchCompletion::default()
    };
    let payload_sources = vec![
        WebSource {
            source_id: crate::agentic::web::source_id_for_url(
                "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
            ),
            rank: Some(1),
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            snippet: Some(
                "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
            ),
            domain: Some("csrc.nist.gov".to_string()),
        },
        WebSource {
            source_id: crate::agentic::web::source_id_for_url(
                "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
            ),
            rank: Some(2),
            url: "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf".to_string(),
            title: Some("State of PQC Readiness 2025".to_string()),
            snippet: Some(
                "State of PQC Readiness 2025 | linked from Building organizational readiness for post-quantum cryptography | guidance on organizational readiness for post-quantum cryptography."
                    .to_string(),
            ),
            domain: Some("trustedcomputinggroup.org".to_string()),
        },
        WebSource {
            source_id: crate::agentic::web::source_id_for_url(
                "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/",
            ),
            rank: Some(3),
            url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
            title: Some(
                "Sponsored: Building organizational readiness for post-quantum cryptography"
                    .to_string(),
            ),
            snippet: Some(
                "Sponsored briefing on organizational readiness for post-quantum cryptography."
                    .to_string(),
            ),
            domain: Some("www.ciodive.com".to_string()),
        },
    ];
    let prioritized_payload_hints = vec![
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.ciodive.com/spons/building-organizational-readiness-for-post-quantum-cryptography/815308/".to_string(),
            title: Some(
                "Sponsored: Building organizational readiness for post-quantum cryptography"
                    .to_string(),
            ),
            excerpt:
                "Sponsored briefing on organizational readiness for post-quantum cryptography."
                    .to_string(),
        },
    ];
    let payload_source_hints = merge_source_hints(
        source_hints_from_web_sources(&payload_sources),
        &prioritized_payload_hints,
    );

    let seeded =
        seed_pending_inventory_from_pre_read_payload_hints(&mut pending, &payload_source_hints);

    assert!(seeded);
    assert!(pending.candidate_urls.iter().any(|url| {
        url.eq_ignore_ascii_case(
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
        )
    }));
    assert!(pending.candidate_source_hints.iter().any(|hint| {
        hint.url.eq_ignore_ascii_case(
            "https://trustedcomputinggroup.org/wp-content/uploads/State-of-PQC-Readiness-2025-November-2025.pdf",
        )
    }));
}

#[test]
fn merge_deterministic_plan_with_pending_inventory_reuses_successful_read_hints_for_probe_grounding(
) {
    let query_contract = research_query_contract();
    let retrieval_contract = research_retrieval_contract();
    let pending = PendingSearchCompletion {
        query: query_contract.clone(),
        query_contract: query_contract.clone(),
        retrieval_contract: Some(retrieval_contract.clone()),
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        min_sources: 2,
        ..PendingSearchCompletion::default()
    };
    let sparse_plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
        ],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2"
                .to_string(),
            title: Some("El marco de ciberseguridad 2.0 del NIST, en detalle | IBM".to_string()),
            excerpt:
                "He aqui todo lo que las empresas deben saber sobre como el marco de ciberseguridad 2.0 del NIST puede mejorar la gestion de riesgos."
                    .to_string(),
        }],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };
    let mut checks = Vec::new();

    let merged = merge_deterministic_plan_with_pending_inventory(
        &retrieval_contract,
        &query_contract,
        2,
        None,
        Some(&pending),
        sparse_plan,
        &mut checks,
    );
    let grounded = constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
        &query_contract,
        Some(&retrieval_contract),
        2,
        &[],
        None,
    );
    let probe = constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        &query_contract,
        Some(&retrieval_contract),
        2,
        &merged.probe_source_hints,
        &grounded,
        None,
    )
    .expect("probe query should be generated");

    assert!(checks
        .iter()
        .any(|check| { check == "web_pre_read_pending_inventory_reused=true" }));
    assert!(checks
        .iter()
        .any(|check| { check == "web_pre_read_pending_inventory_successful_read_hints=1" }));
    assert!(merged.probe_source_hints.iter().any(|hint| {
        hint.url
            .eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")
    }));
    assert!(probe.contains("\"FIPS 203\""), "probe={probe}");
    assert!(probe.contains("\"FIPS 204\""), "probe={probe}");
    assert!(probe.contains("\"FIPS 205\""), "probe={probe}");
}

#[test]
fn briefing_authority_hint_read_recovery_urls_preserve_one_authority_slot_and_one_distinct_support_slot(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
    let deterministic_plan = PreReadCandidatePlan {
        candidate_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt:
                "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                    .to_string(),
        }],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };
    let discovery_hints = vec![
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt:
                "The new public-key cryptography standards will specify additional digital signature, public-key encryption, and key-establishment algorithms."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms"
                .to_string(),
            title: Some(
                "NIST Announces First Four Quantum-Resistant Cryptographic Algorithms"
                    .to_string(),
            ),
            excerpt:
                "NIST selected CRYSTALS-Kyber, CRYSTALS-Dilithium, SPHINCS+, and FALCON."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some("Federal Information Processing Standard (FIPS) 203".to_string()),
            excerpt:
                "NIST IR 8413 Update 1 references FIPS 203 as part of the post-quantum cryptography standards set."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some("Federal Information Processing Standard (FIPS) 204".to_string()),
            excerpt:
                "NIST IR 8413 Update 1 references FIPS 204 as part of the post-quantum cryptography standards set."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
            title: Some("Federal Information Processing Standard (FIPS) 205".to_string()),
            excerpt:
                "NIST IR 8413 Update 1 references FIPS 205 as part of the post-quantum cryptography standards set."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
                .to_string(),
            title: Some(
                "Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 Update 1 summarizes the standardization process and references FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        },
    ];

    let urls = briefing_authority_hint_read_recovery_urls(
        &retrieval_contract,
        query,
        2,
        &deterministic_plan,
        &[],
        &discovery_hints,
        None,
        2,
    );

    assert_eq!(urls.len(), 2, "{urls:?}");
    assert!(
        urls.iter()
            .any(|url| url.starts_with("https://csrc.nist.gov/pubs/fips/20")),
        "{urls:?}"
    );
    assert!(
        urls.iter()
            .any(|url| url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/fips/203/final")),
        "{urls:?}"
    );
    assert!(
        urls.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf"
            )
                || url.eq_ignore_ascii_case(
                    "https://www.nist.gov/news-events/news/2022/07/nist-announces-first-four-quantum-resistant-cryptographic-algorithms"
                )
        }),
        "{urls:?}"
    );
}

#[test]
fn briefing_authority_hint_read_recovery_urls_choose_official_news_when_no_pdf_domain_available(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
    let deterministic_plan = PreReadCandidatePlan {
        candidate_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "The latest NIST post-quantum cryptography standards track FIPS 203, FIPS 204, and FIPS 205."
                    .to_string(),
        }],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };
    let discovery_hints = vec![
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some("Federal Information Processing Standard (FIPS) 203".to_string()),
            excerpt:
                "NIST IR 8413 Update 1 references FIPS 203 as part of the post-quantum cryptography standards set."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                .to_string(),
            title: Some(
                "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                    .to_string(),
            ),
            excerpt:
                "NIST released the first three finalized post-quantum encryption standards and urged migration to the new standards."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
                .to_string(),
            title: Some("Post-Quantum Cryptography Standardization".to_string()),
            excerpt:
                "NIST project page for the latest post-quantum cryptography standards and standardization updates."
                    .to_string(),
        },
    ];

    let urls = briefing_authority_hint_read_recovery_urls(
        &retrieval_contract,
        query,
        2,
        &deterministic_plan,
        &[],
        &discovery_hints,
        None,
        2,
    );

    assert_eq!(urls.len(), 2, "{urls:?}");
    assert!(
        urls.iter()
            .any(|url| url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/fips/203/final")),
        "{urls:?}"
    );
    assert!(
        urls.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            )
        }),
        "{urls:?}"
    );
}

#[test]
fn briefing_authority_hint_read_recovery_urls_fill_recovery_batch_after_single_authority_slot()
{
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
    let deterministic_plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
            "https://www.nist.gov/about-nist".to_string(),
            "https://www.nist.gov/standards".to_string(),
            "https://www.nist.gov/publications".to_string(),
            "https://www.nist.gov/standards-measurements".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                .to_string(),
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                title: Some("Cybersecurity and privacy | NIST".to_string()),
                excerpt:
                    "NIST advances standards, guidelines, best practices, and resources for cybersecurity."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum standards."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some(
                    "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                        .to_string(),
                ),
                excerpt:
                    "Finalized NIST FIPS 203 post-quantum cryptography standard.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                title: Some(
                    "FIPS 204, Module-Lattice-Based Digital Signature Standard".to_string(),
                ),
                excerpt:
                    "Finalized NIST FIPS 204 post-quantum cryptography standard.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
                title: Some(
                    "FIPS 205, Stateless Hash-Based Digital Signature Standard".to_string(),
                ),
                excerpt:
                    "Finalized NIST FIPS 205 post-quantum cryptography standard.".to_string(),
            },
        ],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };

    let urls = briefing_authority_hint_read_recovery_urls(
        &retrieval_contract,
        query,
        2,
        &deterministic_plan,
        &[],
        &deterministic_plan.candidate_source_hints,
        None,
        2,
    );

    assert_eq!(urls.len(), 2, "{urls:?}");
    assert!(
        urls.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            ) || url.starts_with("https://csrc.nist.gov/pubs/fips/20")
        }),
        "{urls:?}"
    );
}

#[test]
fn distinct_domain_preserving_selected_urls_promotes_official_support_into_initial_briefing_batch(
) {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
    let candidate_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
        "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved".to_string(),
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
    ];

    let selected = distinct_domain_preserving_selected_urls(
        &retrieval_contract,
        query,
        &candidate_urls,
        2,
    );

    assert_eq!(
        selected,
        vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                .to_string(),
        ]
    );
}

#[test]
fn merged_candidate_urls_promote_semantic_distinct_host_support_into_initial_briefing_batch() {
    let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
    let selected_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
            .to_string(),
    ];
    let deterministic_candidate_urls = selected_urls.clone();
    let semantic_aligned_discovery_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
            .to_string(),
        "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
            .to_string(),
    ];

    let merged = merge_candidate_urls_preserving_order(
        &selected_urls,
        &deterministic_candidate_urls,
        &semantic_aligned_discovery_urls,
    );
    let promoted =
        distinct_domain_preserving_selected_urls(&retrieval_contract, query, &merged, 2);

    assert_eq!(
        promoted,
        vec![
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                .to_string(),
        ]
    );
}

#[test]
fn selected_source_alignment_uses_selected_surface_hints_for_document_briefings() {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
    let selected_urls = vec![
        "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
        "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
        "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
    ];
    let discovery_aligned_urls =
        vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()];
    let source_hints = vec![
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some(
                "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                    .to_string(),
            ),
            excerpt:
                "NIST IR 8413 Update 1 references FIPS 203, FIPS 204, and FIPS 205 as the finalized post-quantum cryptography standards."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            title: Some(
                "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard | CSRC"
                    .to_string(),
            ),
            excerpt:
                "Federal Information Processing Standard FIPS 203 specifies ML-KEM as a finalized NIST post-quantum cryptography standard."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            title: Some(
                "FIPS 204, Module-Lattice-Based Digital Signature Standard | CSRC"
                    .to_string(),
            ),
            excerpt:
                "Federal Information Processing Standard FIPS 204 specifies ML-DSA as a finalized NIST post-quantum cryptography standard."
                    .to_string(),
        },
        PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/fips/205/final".to_string(),
            title: Some(
                "FIPS 205, Stateless Hash-Based Digital Signature Standard | CSRC"
                    .to_string(),
            ),
            excerpt:
                "Federal Information Processing Standard FIPS 205 specifies SLH-DSA as a finalized NIST post-quantum cryptography standard."
                    .to_string(),
        },
    ];

    let aligned = selected_source_alignment_urls(
        query,
        &retrieval_contract,
        &selected_urls,
        &discovery_aligned_urls,
        &source_hints,
        None,
    );

    assert_eq!(aligned.len(), selected_urls.len(), "{aligned:?}");
    assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/203/final".to_string()));
    assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/204/final".to_string()));
    assert!(aligned.contains(&"https://csrc.nist.gov/pubs/fips/205/final".to_string()));
}

#[test]
fn briefing_authority_hint_read_recovery_urls_prefer_grounded_support_over_generic_same_host_neighbors(
) {
    let query =
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
    let retrieval_contract =
        crate::agentic::web::derive_web_retrieval_contract(query, Some(query)).unwrap();
    let deterministic_plan = PreReadCandidatePlan {
        candidate_urls: vec![
            "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
            "https://www.nist.gov/about-nist".to_string(),
            "https://www.nist.gov/standards".to_string(),
            "https://www.nist.gov/publications".to_string(),
            "https://www.nist.gov/standards-measurements".to_string(),
            "https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography"
                .to_string(),
            "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                .to_string(),
        ],
        candidate_source_hints: vec![
            PendingSearchReadSummary {
                url: "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                title: Some("Cybersecurity and privacy | NIST".to_string()),
                excerpt:
                    "NIST advances standards, guidelines, best practices, and resources for cybersecurity."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/about-nist".to_string(),
                title: Some("About NIST".to_string()),
                excerpt: "Overview of the National Institute of Standards and Technology."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography"
                    .to_string(),
                title: Some("What Is Post-Quantum Cryptography? | NIST".to_string()),
                excerpt:
                    "Overview of post-quantum cryptography and why NIST is standardizing new algorithms."
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                title: Some(
                    "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard"
                        .to_string(),
                ),
                excerpt:
                    "Finalized NIST FIPS 203 post-quantum cryptography standard.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                        .to_string(),
                ),
                excerpt:
                    "NIST released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum standards."
                        .to_string(),
            },
        ],
        requires_constraint_search_probe: true,
        ..PreReadCandidatePlan::default()
    };

    let urls = briefing_authority_hint_read_recovery_urls(
        &retrieval_contract,
        query,
        2,
        &deterministic_plan,
        &[],
        &deterministic_plan.candidate_source_hints,
        None,
        2,
    );

    assert_eq!(urls.len(), 2, "{urls:?}");
    assert!(
        urls.iter()
            .all(|url| !url.eq_ignore_ascii_case("https://www.nist.gov/about-nist")),
        "{urls:?}"
    );
    assert!(
        urls.iter().any(|url| {
            url.eq_ignore_ascii_case(
                "https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography"
            ) || url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/fips/203/final")
                || url.eq_ignore_ascii_case(
                    "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                )
        }),
        "{urls:?}"
    );
}
